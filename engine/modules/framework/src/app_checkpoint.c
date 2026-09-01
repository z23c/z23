/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure checkpoint layout, admission, compatibility, and SHA3 codecs. No App
 * database, CAS, journal, route, wallet, or generation switch is opened here. */

#include "framework/app_checkpoint.h"

#include "crypto/sha3.h"
#include "framework/app_definition.h"

#include <string.h>

static bool digest_is_zero(const uint8_t digest[32])
{
    uint8_t seen = 0;
    for (size_t i = 0; i < 32; i++)
        seen |= digest[i];
    return seen == 0;
}

static bool power_of_two(uint32_t value)
{
    return value != 0 && (value & (value - 1u)) == 0;
}

static void digest_u32(struct sha3_256_ctx *ctx, uint32_t value)
{
    uint8_t encoded[4];
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, encoded, sizeof(encoded));
}

static void digest_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t encoded[8];
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, encoded, sizeof(encoded));
}

static void digest_text(struct sha3_256_ctx *ctx, const char *text,
                        size_t capacity)
{
    size_t length = strnlen(text, capacity);
    digest_u32(ctx, (uint32_t)length);
    sha3_256_write(ctx, (const uint8_t *)text, length);
}

bool zcl_app_state_chunk_digest_v1(const uint8_t *bytes, uint32_t length,
                                   uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (!bytes || length == 0 || length > ZCL_APP_STATE_CHUNK_BYTES_V1)
        return false;
    static const uint8_t domain[] = "zcl.app.state_chunk.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    digest_u32(&ctx, length);
    sha3_256_write(&ctx, bytes, length);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool zcl_app_checkpoint_empty_component_root_v1(uint32_t component,
                                                uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (component < ZCL_APP_CHECKPOINT_COMPONENT_EVENTS ||
        component > ZCL_APP_CHECKPOINT_COMPONENT_JOBS)
        return false;
    static const uint8_t domain[] = "zcl.app.component.empty.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    digest_u32(&ctx, component);
    sha3_256_finalize(&ctx, out);
    return true;
}

static void digest_cursor(
    struct sha3_256_ctx *ctx,
    const struct zcl_app_checkpoint_cursor_v1 *cursor)
{
    digest_u64(ctx, cursor->sequence);
    sha3_256_write(ctx, cursor->root, 32);
}

static void checkpoint_digest_begin(
    struct sha3_256_ctx *ctx,
    const struct zcl_app_checkpoint_manifest_v1 *manifest)
{
    static const uint8_t domain[] = "zcl.app.checkpoint.v1";
    sha3_256_init(ctx);
    sha3_256_write(ctx, domain, sizeof(domain));
    digest_u32(ctx, manifest->schema_version);
    digest_text(ctx, manifest->app_id, sizeof(manifest->app_id));
    sha3_256_write(ctx, manifest->instance_id, 32);
    sha3_256_write(ctx, manifest->publisher_root, 32);
    sha3_256_write(ctx, manifest->package_root, 32);
    sha3_256_write(ctx, manifest->artifact_root, 32);
    digest_u64(ctx, manifest->activation_generation);
    sha3_256_write(ctx, manifest->activation_generation_root, 32);
    digest_u64(ctx, manifest->state_generation);
    sha3_256_write(ctx, manifest->state_generation_root, 32);
    digest_u64(ctx, manifest->grant_revision);
    sha3_256_write(ctx, manifest->grant_root, 32);
    digest_u32(ctx, manifest->storage_format);
    digest_u32(ctx, manifest->storage_class);
    digest_u32(ctx, manifest->app_schema_version);
    digest_u32(ctx, manifest->sdk_abi);
    digest_u32(ctx, manifest->logical_root_codec);
    sha3_256_write(ctx, manifest->migration_lineage_root, 32);
    sha3_256_write(ctx, manifest->sqlite_image_root, 32);
    sha3_256_write(ctx, manifest->logical_state_root, 32);
    digest_cursor(ctx, &manifest->events);
    digest_cursor(ctx, &manifest->outbox);
    digest_cursor(ctx, &manifest->subscriptions);
    digest_cursor(ctx, &manifest->routes);
    digest_cursor(ctx, &manifest->jobs);
    digest_u32(ctx, manifest->chunk_size);
    digest_u32(ctx, manifest->chunk_count);
    digest_u64(ctx, manifest->total_bytes);
}

static void checkpoint_digest_finish(
    struct sha3_256_ctx *ctx,
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    uint8_t out[32])
{
    digest_u32(ctx, manifest->creation_cause);
    digest_u32(ctx, manifest->state_origin);
    digest_u32(ctx, manifest->outbox_mode);
    digest_u32(ctx, manifest->has_parent);
    sha3_256_write(ctx, manifest->parent_checkpoint_root, 32);
    sha3_256_finalize(ctx, out);
}

/* Validate layout while feeding both identities in one descriptor pass. */
static enum zcl_app_checkpoint_result validate_and_digest_chunks(
    uint32_t chunk_size,
    uint64_t total_bytes,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    uint8_t image_root[32],
    struct sha3_256_ctx *checkpoint_ctx)
{
    memset(image_root, 0, 32);
    if (!chunks || chunk_size != ZCL_APP_STATE_CHUNK_BYTES_V1 ||
        total_bytes == 0 || total_bytes > ZCL_APP_STATE_BYTES_MAX_V1 ||
        chunk_count == 0 || chunk_count > ZCL_APP_STATE_CHUNK_MAX_V1)
        return ZCL_APP_CHECKPOINT_CHUNK_LAYOUT;
    uint64_t expected_count =
        1u + (total_bytes - 1u) / ZCL_APP_STATE_CHUNK_BYTES_V1;
    if (expected_count != chunk_count)
        return ZCL_APP_CHECKPOINT_CHUNK_LAYOUT;
    static const uint8_t domain[] = "zcl.app.sqlite_image.v1";
    struct sha3_256_ctx image_ctx;
    sha3_256_init(&image_ctx);
    sha3_256_write(&image_ctx, domain, sizeof(domain));
    digest_u32(&image_ctx, chunk_size);
    digest_u32(&image_ctx, (uint32_t)chunk_count);
    digest_u64(&image_ctx, total_bytes);
    for (size_t i = 0; i < chunk_count; i++) {
        uint64_t offset = (uint64_t)i * ZCL_APP_STATE_CHUNK_BYTES_V1;
        uint64_t remaining = total_bytes - offset;
        uint32_t length = remaining > ZCL_APP_STATE_CHUNK_BYTES_V1
                              ? ZCL_APP_STATE_CHUNK_BYTES_V1
                              : (uint32_t)remaining;
        if (i > UINT32_MAX || chunks[i].index != (uint32_t)i ||
            chunks[i].offset != offset || chunks[i].length != length ||
            digest_is_zero(chunks[i].digest))
            return ZCL_APP_CHECKPOINT_CHUNK_LAYOUT;
        digest_u32(&image_ctx, chunks[i].index);
        digest_u32(&image_ctx, chunks[i].length);
        digest_u64(&image_ctx, chunks[i].offset);
        sha3_256_write(&image_ctx, chunks[i].digest, 32);
        if (checkpoint_ctx) {
            digest_u32(checkpoint_ctx, chunks[i].index);
            digest_u32(checkpoint_ctx, chunks[i].length);
            digest_u64(checkpoint_ctx, chunks[i].offset);
            sha3_256_write(checkpoint_ctx, chunks[i].digest, 32);
        }
    }
    sha3_256_finalize(&image_ctx, image_root);
    return ZCL_APP_CHECKPOINT_OK;
}

bool zcl_app_checkpoint_image_root_v1(
    uint32_t chunk_size,
    uint64_t total_bytes,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    uint8_t out[32])
{
    if (!out)
        return false;
    return validate_and_digest_chunks(
               chunk_size, total_bytes, chunks, chunk_count, out, NULL) ==
           ZCL_APP_CHECKPOINT_OK;
}

static bool cursor_valid(const struct zcl_app_checkpoint_cursor_v1 *cursor,
                         uint32_t component)
{
    if (cursor->sequence > 0)
        return !digest_is_zero(cursor->root);
    uint8_t empty_root[32];
    return zcl_app_checkpoint_empty_component_root_v1(component, empty_root) &&
           memcmp(cursor->root, empty_root, 32) == 0;
}

static bool cursor_extends(
    const struct zcl_app_checkpoint_cursor_v1 *child,
    const struct zcl_app_checkpoint_cursor_v1 *parent)
{
    return child->sequence > parent->sequence ||
           (child->sequence == parent->sequence &&
            memcmp(child->root, parent->root, 32) == 0);
}

static bool warm_cache_shape_valid(const struct zcl_app_warm_cache_v1 *cache)
{
    if (cache->present == 0) {
        return cache->format_version == 0 && cache->architecture == 0 &&
               cache->endianness == 0 && cache->data_model_bits == 0 &&
               cache->page_size == 0 && cache->alignment == 0 &&
               cache->encoding_flags == 0 && cache->region_count == 0 &&
               cache->cpu_feature_floor[0] == 0 &&
               cache->cpu_feature_floor[1] == 0 &&
               cache->byte_length == 0 && digest_is_zero(cache->root);
    }
    if (cache->present != 1 ||
        cache->format_version != ZCL_APP_WARM_CACHE_FORMAT_V1 ||
        (cache->architecture != ZCL_APP_WARM_ARCH_X86_64 &&
         cache->architecture != ZCL_APP_WARM_ARCH_AARCH64) ||
        (cache->endianness != ZCL_APP_WARM_ENDIAN_LITTLE &&
         cache->endianness != ZCL_APP_WARM_ENDIAN_BIG) ||
        (cache->data_model_bits != 32 && cache->data_model_bits != 64) ||
        !power_of_two(cache->page_size) || cache->page_size < 4096 ||
        cache->page_size > 65536 || !power_of_two(cache->alignment) ||
        cache->alignment > cache->page_size ||
        cache->encoding_flags != ZCL_APP_WARM_REQUIRED_ENCODING_V1 ||
        cache->region_count == 0 || cache->region_count > 1024 ||
        cache->byte_length == 0 || cache->byte_length > UINT64_C(4294967296) ||
        digest_is_zero(cache->root))
        return false;
    return true;
}

static bool identity_roots_valid(
    const struct zcl_app_checkpoint_manifest_v1 *manifest)
{
    return !digest_is_zero(manifest->instance_id) &&
           !digest_is_zero(manifest->publisher_root) &&
           !digest_is_zero(manifest->package_root) &&
           !digest_is_zero(manifest->artifact_root) &&
           !digest_is_zero(manifest->activation_generation_root) &&
           !digest_is_zero(manifest->state_generation_root) &&
           !digest_is_zero(manifest->grant_root);
}

static bool causality_valid(
    const struct zcl_app_checkpoint_manifest_v1 *manifest)
{
    if (manifest->has_parent > 1)
        return false;
    if ((manifest->has_parent == 0) !=
        digest_is_zero(manifest->parent_checkpoint_root))
        return false;
    if (manifest->creation_cause < ZCL_APP_CHECKPOINT_CAUSE_INITIAL ||
        manifest->creation_cause > ZCL_APP_CHECKPOINT_CAUSE_RESTORE)
        return false;
    if (manifest->creation_cause == ZCL_APP_CHECKPOINT_CAUSE_INITIAL)
        return manifest->has_parent == 0 &&
               manifest->state_origin == ZCL_APP_CHECKPOINT_ORIGIN_LIVE;
    if (manifest->creation_cause == ZCL_APP_CHECKPOINT_CAUSE_LLM_FORK)
        return manifest->has_parent == 1 &&
               manifest->state_origin ==
                   ZCL_APP_CHECKPOINT_ORIGIN_ISOLATED_FORK;
    if (manifest->creation_cause == ZCL_APP_CHECKPOINT_CAUSE_SCENARIO_FIXTURE)
        return manifest->has_parent == 1 &&
               manifest->state_origin ==
                   ZCL_APP_CHECKPOINT_ORIGIN_SYNTHETIC_FIXTURE;
    return manifest->has_parent == 1 &&
           manifest->state_origin >= ZCL_APP_CHECKPOINT_ORIGIN_LIVE &&
           manifest->state_origin <=
               ZCL_APP_CHECKPOINT_ORIGIN_SYNTHETIC_FIXTURE;
}

static enum zcl_app_checkpoint_result validate_structure_and_digest(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    uint8_t checkpoint_root[32])
{
    if (checkpoint_root)
        memset(checkpoint_root, 0, 32);
    if (!manifest)
        return ZCL_APP_CHECKPOINT_NULL;
    if (manifest->struct_size != sizeof(*manifest) ||
        manifest->schema_version != ZCL_APP_CHECKPOINT_V1)
        return ZCL_APP_CHECKPOINT_SCHEMA;
    if (!zcl_app_definition_id_valid_v1(manifest->app_id))
        return ZCL_APP_CHECKPOINT_APP_ID;
    if (!identity_roots_valid(manifest))
        return ZCL_APP_CHECKPOINT_IDENTITY;
    if (manifest->activation_generation == 0 ||
        manifest->state_generation == 0)
        return ZCL_APP_CHECKPOINT_GENERATION;
    if (manifest->grant_revision == 0)
        return ZCL_APP_CHECKPOINT_GRANT;
    if (manifest->storage_format != ZCL_APP_CHECKPOINT_STORAGE_SQLITE3 ||
        manifest->app_schema_version == 0 || manifest->sdk_abi == 0 ||
        manifest->logical_root_codec != ZCL_APP_LOGICAL_ROOT_CODEC_V1 ||
        digest_is_zero(manifest->migration_lineage_root))
        return ZCL_APP_CHECKPOINT_STATE_SCHEMA;
    if (manifest->storage_class !=
        ZCL_APP_CHECKPOINT_CLASS_PRIVATE_LOCAL)
        return ZCL_APP_CHECKPOINT_STORAGE_CLASS;
    if (digest_is_zero(manifest->sqlite_image_root) ||
        digest_is_zero(manifest->logical_state_root))
        return ZCL_APP_CHECKPOINT_ROOT;
    if (!cursor_valid(&manifest->events,
                      ZCL_APP_CHECKPOINT_COMPONENT_EVENTS) ||
        !cursor_valid(&manifest->outbox,
                      ZCL_APP_CHECKPOINT_COMPONENT_OUTBOX) ||
        !cursor_valid(&manifest->subscriptions,
                      ZCL_APP_CHECKPOINT_COMPONENT_SUBSCRIPTIONS) ||
        !cursor_valid(&manifest->routes,
                      ZCL_APP_CHECKPOINT_COMPONENT_ROUTES) ||
        !cursor_valid(&manifest->jobs, ZCL_APP_CHECKPOINT_COMPONENT_JOBS))
        return ZCL_APP_CHECKPOINT_CURSOR;
    if (manifest->chunk_count != chunk_count)
        return ZCL_APP_CHECKPOINT_CHUNK_LAYOUT;
    struct sha3_256_ctx checkpoint_ctx;
    if (checkpoint_root)
        checkpoint_digest_begin(&checkpoint_ctx, manifest);
    uint8_t image_root[32];
    enum zcl_app_checkpoint_result chunks_result =
        validate_and_digest_chunks(
            manifest->chunk_size, manifest->total_bytes, chunks, chunk_count,
            image_root, checkpoint_root ? &checkpoint_ctx : NULL);
    if (chunks_result != ZCL_APP_CHECKPOINT_OK)
        return chunks_result;
    if (memcmp(image_root, manifest->sqlite_image_root, 32) != 0)
        return ZCL_APP_CHECKPOINT_IMAGE_ROOT;
    if (!causality_valid(manifest))
        return ZCL_APP_CHECKPOINT_CAUSALITY;
    if (manifest->state_origin == ZCL_APP_CHECKPOINT_ORIGIN_LIVE) {
        if (manifest->outbox_mode != ZCL_APP_CHECKPOINT_OUTBOX_CONTROLLED)
            return ZCL_APP_CHECKPOINT_SIDE_EFFECT;
    } else if ((manifest->state_origin !=
                    ZCL_APP_CHECKPOINT_ORIGIN_ISOLATED_FORK &&
                manifest->state_origin !=
                    ZCL_APP_CHECKPOINT_ORIGIN_SYNTHETIC_FIXTURE) ||
               manifest->outbox_mode !=
                   ZCL_APP_CHECKPOINT_OUTBOX_QUARANTINED) {
        return ZCL_APP_CHECKPOINT_SIDE_EFFECT;
    }
    if (checkpoint_root)
        checkpoint_digest_finish(
            &checkpoint_ctx, manifest, checkpoint_root);
    return ZCL_APP_CHECKPOINT_OK;
}

enum zcl_app_checkpoint_result zcl_app_checkpoint_validate_structure_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count)
{
    return validate_structure_and_digest(
        manifest, chunks, chunk_count, NULL);
}

static enum zcl_app_checkpoint_result validate_lineage_checked(
    const struct zcl_app_checkpoint_manifest_v1 *child,
    const struct zcl_app_checkpoint_manifest_v1 *parent,
    const uint8_t parent_root[32])
{
    if (child->has_parent != 1)
        return ZCL_APP_CHECKPOINT_CAUSALITY;
    if (strcmp(child->app_id, parent->app_id) != 0 ||
        memcmp(child->instance_id, parent->instance_id, 32) != 0)
        return ZCL_APP_CHECKPOINT_CAUSALITY;
    if (memcmp(parent_root, child->parent_checkpoint_root, 32) != 0)
        return ZCL_APP_CHECKPOINT_CAUSALITY;
    if (child->state_origin < parent->state_origin)
        return ZCL_APP_CHECKPOINT_ADMISSION;
    if (child->creation_cause != ZCL_APP_CHECKPOINT_CAUSE_LLM_FORK &&
        child->creation_cause !=
            ZCL_APP_CHECKPOINT_CAUSE_SCENARIO_FIXTURE &&
        child->state_origin != parent->state_origin)
        return ZCL_APP_CHECKPOINT_ADMISSION;
    bool new_state_generation =
        child->creation_cause == ZCL_APP_CHECKPOINT_CAUSE_ROLLBACK ||
        child->creation_cause == ZCL_APP_CHECKPOINT_CAUSE_LLM_FORK ||
        child->creation_cause ==
            ZCL_APP_CHECKPOINT_CAUSE_SCENARIO_FIXTURE ||
        child->creation_cause == ZCL_APP_CHECKPOINT_CAUSE_MIGRATION ||
        child->creation_cause == ZCL_APP_CHECKPOINT_CAUSE_RESTORE;
    if (new_state_generation) {
        if (child->state_generation <= parent->state_generation ||
            memcmp(child->state_generation_root,
                   parent->state_generation_root, 32) == 0)
            return ZCL_APP_CHECKPOINT_GENERATION;
    } else if (child->state_generation != parent->state_generation ||
               memcmp(child->state_generation_root,
                      parent->state_generation_root, 32) != 0) {
        return ZCL_APP_CHECKPOINT_GENERATION;
    }
    if (child->creation_cause != ZCL_APP_CHECKPOINT_CAUSE_ROLLBACK &&
        child->creation_cause != ZCL_APP_CHECKPOINT_CAUSE_RESTORE &&
        (!cursor_extends(&child->events, &parent->events) ||
         !cursor_extends(&child->outbox, &parent->outbox) ||
         !cursor_extends(&child->subscriptions, &parent->subscriptions) ||
         !cursor_extends(&child->routes, &parent->routes) ||
         !cursor_extends(&child->jobs, &parent->jobs)))
        return ZCL_APP_CHECKPOINT_CURSOR;
    return ZCL_APP_CHECKPOINT_OK;
}

enum zcl_app_checkpoint_result zcl_app_checkpoint_validate_lineage_v1(
    const struct zcl_app_checkpoint_manifest_v1 *child,
    const struct zcl_app_state_chunk_v1 *child_chunks,
    size_t child_chunk_count,
    const struct zcl_app_checkpoint_manifest_v1 *parent,
    const struct zcl_app_state_chunk_v1 *parent_chunks,
    size_t parent_chunk_count)
{
    enum zcl_app_checkpoint_result child_result =
        validate_structure_and_digest(
            child, child_chunks, child_chunk_count, NULL);
    if (child_result != ZCL_APP_CHECKPOINT_OK)
        return child_result;
    uint8_t parent_root[32];
    enum zcl_app_checkpoint_result parent_result =
        validate_structure_and_digest(
            parent, parent_chunks, parent_chunk_count, parent_root);
    if (parent_result != ZCL_APP_CHECKPOINT_OK)
        return parent_result;
    return validate_lineage_checked(child, parent, parent_root);
}

static bool exact_binding(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_checkpoint_expected_v1 *expected)
{
    return strcmp(manifest->app_id, expected->app_id) == 0 &&
           memcmp(manifest->instance_id, expected->instance_id, 32) == 0 &&
           memcmp(manifest->publisher_root, expected->publisher_root, 32) == 0 &&
           memcmp(manifest->package_root, expected->package_root, 32) == 0 &&
           memcmp(manifest->artifact_root, expected->artifact_root, 32) == 0 &&
           manifest->activation_generation == expected->activation_generation &&
           memcmp(manifest->activation_generation_root,
                  expected->activation_generation_root, 32) == 0 &&
           manifest->state_generation == expected->state_generation &&
           memcmp(manifest->state_generation_root,
                  expected->state_generation_root, 32) == 0 &&
           manifest->grant_revision == expected->grant_revision &&
           memcmp(manifest->grant_root, expected->grant_root, 32) == 0 &&
           manifest->app_schema_version == expected->app_schema_version &&
           manifest->sdk_abi == expected->sdk_abi &&
           manifest->logical_root_codec == expected->logical_root_codec &&
           memcmp(manifest->migration_lineage_root,
                  expected->migration_lineage_root, 32) == 0;
}

enum zcl_app_checkpoint_result zcl_app_checkpoint_validate_admission_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    const struct zcl_app_checkpoint_expected_v1 *expected,
    const struct zcl_app_checkpoint_acceptance_v1 *acceptance,
    const struct zcl_app_checkpoint_manifest_v1 *parent,
    const struct zcl_app_state_chunk_v1 *parent_chunks,
    size_t parent_chunk_count,
    const struct zcl_app_checkpoint_acceptance_v1 *parent_acceptance)
{
    uint8_t checkpoint_root[32];
    enum zcl_app_checkpoint_result result =
        validate_structure_and_digest(
            manifest, chunks, chunk_count, checkpoint_root);
    if (result != ZCL_APP_CHECKPOINT_OK)
        return result;
    if (!expected || expected->struct_size != sizeof(*expected) ||
        !zcl_app_definition_id_valid_v1(expected->app_id) ||
        digest_is_zero(expected->checkpoint_root) ||
        expected->accepting_service_id == 0 ||
        expected->control_sequence == 0 ||
        digest_is_zero(expected->control_event_id) ||
        digest_is_zero(expected->control_segment_root))
        return ZCL_APP_CHECKPOINT_EXPECTED_BINDING;
    if (expected->admission < ZCL_APP_CHECKPOINT_ADMISSION_RESTORE_SOURCE ||
        expected->admission >
            ZCL_APP_CHECKPOINT_ADMISSION_PRODUCTION_SWITCH)
        return ZCL_APP_CHECKPOINT_ADMISSION;
    if (memcmp(checkpoint_root, expected->checkpoint_root, 32) != 0)
        return ZCL_APP_CHECKPOINT_EXPECTED_BINDING;
    enum zcl_app_checkpoint_result acceptance_result =
        zcl_app_checkpoint_acceptance_validate_v1(
            acceptance, checkpoint_root);
    if (acceptance_result != ZCL_APP_CHECKPOINT_OK)
        return acceptance_result;
    if (acceptance->accepting_service_id !=
            expected->accepting_service_id ||
        acceptance->control_sequence != expected->control_sequence ||
        memcmp(acceptance->control_event_id,
               expected->control_event_id, 32) != 0 ||
        memcmp(acceptance->control_segment_root,
               expected->control_segment_root, 32) != 0)
        return ZCL_APP_CHECKPOINT_ACCEPTANCE;
    if (!exact_binding(manifest, expected))
        return ZCL_APP_CHECKPOINT_EXPECTED_BINDING;
    if (!zcl_app_checkpoint_cursors_meet_floors_v1(
            manifest, &expected->cursor_floors))
        return ZCL_APP_CHECKPOINT_ADMISSION;
    if (manifest->has_parent == 1) {
        if (!parent || !parent_chunks || parent_chunk_count == 0 ||
            !parent_acceptance ||
            digest_is_zero(expected->parent_acceptance_receipt_root))
            return ZCL_APP_CHECKPOINT_CAUSALITY;
        if (!digest_is_zero(expected->instance_creation_receipt_root))
            return ZCL_APP_CHECKPOINT_ADMISSION;
        uint8_t parent_root[32];
        enum zcl_app_checkpoint_result lineage_result =
            validate_structure_and_digest(
                parent, parent_chunks, parent_chunk_count, parent_root);
        if (lineage_result == ZCL_APP_CHECKPOINT_OK)
            lineage_result = validate_lineage_checked(
                manifest, parent, parent_root);
        if (lineage_result != ZCL_APP_CHECKPOINT_OK)
            return lineage_result;
        enum zcl_app_checkpoint_result parent_acceptance_result =
            zcl_app_checkpoint_acceptance_validate_v1(
                parent_acceptance, manifest->parent_checkpoint_root);
        if (parent_acceptance_result != ZCL_APP_CHECKPOINT_OK)
            return parent_acceptance_result;
        uint8_t parent_receipt_root[32];
        if (parent_acceptance->accepting_service_id !=
                expected->accepting_service_id ||
            parent_acceptance->control_sequence >=
                acceptance->control_sequence ||
            !zcl_app_checkpoint_acceptance_digest_v1(
                parent_acceptance, parent_receipt_root) ||
            memcmp(parent_receipt_root,
                   expected->parent_acceptance_receipt_root, 32) != 0)
            return ZCL_APP_CHECKPOINT_ACCEPTANCE;
    } else {
        if (parent || parent_chunks || parent_chunk_count != 0 ||
            parent_acceptance ||
            !digest_is_zero(expected->parent_acceptance_receipt_root))
            return ZCL_APP_CHECKPOINT_CAUSALITY;
        if (digest_is_zero(expected->instance_creation_receipt_root))
            return ZCL_APP_CHECKPOINT_ADMISSION;
    }
    if (expected->admission ==
            ZCL_APP_CHECKPOINT_ADMISSION_PRODUCTION_SWITCH &&
        (manifest->state_origin != ZCL_APP_CHECKPOINT_ORIGIN_LIVE ||
         manifest->outbox_mode != ZCL_APP_CHECKPOINT_OUTBOX_CONTROLLED))
        return ZCL_APP_CHECKPOINT_ADMISSION;
    bool scenario_context =
        !digest_is_zero(expected->scenario_principal_root) ||
        expected->scenario_grant_revision != 0 ||
        !digest_is_zero(expected->scenario_grant_root) ||
        !digest_is_zero(expected->attenuation_receipt_root);
    if (expected->admission ==
        ZCL_APP_CHECKPOINT_ADMISSION_ISOLATED_SCENARIO) {
        if (manifest->state_origin == ZCL_APP_CHECKPOINT_ORIGIN_LIVE ||
            manifest->outbox_mode != ZCL_APP_CHECKPOINT_OUTBOX_QUARANTINED ||
            digest_is_zero(expected->scenario_principal_root) ||
            expected->scenario_grant_revision == 0 ||
            digest_is_zero(expected->scenario_grant_root) ||
            digest_is_zero(expected->attenuation_receipt_root) ||
            memcmp(expected->scenario_grant_root,
                   manifest->grant_root, 32) == 0)
            return ZCL_APP_CHECKPOINT_ADMISSION;
    } else if (scenario_context) {
        return ZCL_APP_CHECKPOINT_ADMISSION;
    }
    return ZCL_APP_CHECKPOINT_OK;
}

bool zcl_app_checkpoint_cursors_meet_floors_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_checkpoint_cursor_floors_v1 *floors)
{
    if (!manifest || !floors || manifest->struct_size != sizeof(*manifest) ||
        manifest->schema_version != ZCL_APP_CHECKPOINT_V1)
        return false;
    return manifest->events.sequence >= floors->events &&
           manifest->outbox.sequence >= floors->outbox &&
           manifest->subscriptions.sequence >= floors->subscriptions &&
           manifest->routes.sequence >= floors->routes &&
           manifest->jobs.sequence >= floors->jobs;
}

bool zcl_app_checkpoint_digest_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    uint8_t out[32])
{
    if (!out)
        return false;
    return validate_structure_and_digest(
               manifest, chunks, chunk_count, out) ==
           ZCL_APP_CHECKPOINT_OK;
}

static void digest_warm_cache(struct sha3_256_ctx *ctx,
                              const struct zcl_app_warm_cache_v1 *cache)
{
    digest_u32(ctx, cache->format_version);
    digest_u32(ctx, cache->architecture);
    digest_u32(ctx, cache->endianness);
    digest_u32(ctx, cache->data_model_bits);
    digest_u32(ctx, cache->page_size);
    digest_u32(ctx, cache->alignment);
    digest_u32(ctx, cache->encoding_flags);
    digest_u32(ctx, cache->region_count);
    digest_u64(ctx, cache->cpu_feature_floor[0]);
    digest_u64(ctx, cache->cpu_feature_floor[1]);
    digest_u64(ctx, cache->byte_length);
    sha3_256_write(ctx, cache->root, 32);
}

bool zcl_app_warm_cache_attachment_digest_v1(
    const uint8_t checkpoint_root[32],
    const struct zcl_app_warm_cache_v1 *cache,
    uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (!checkpoint_root || digest_is_zero(checkpoint_root) || !cache ||
        cache->present != 1 || !warm_cache_shape_valid(cache))
        return false;
    static const uint8_t domain[] = "zcl.app.warm_cache_attachment.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    sha3_256_write(&ctx, checkpoint_root, 32);
    digest_warm_cache(&ctx, cache);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool zcl_app_warm_cache_compatible_v1(
    const struct zcl_app_warm_cache_v1 *cache,
    const struct zcl_app_warm_cache_host_v1 *host)
{
    if (!cache || !host || host->struct_size != sizeof(*host) ||
        cache->present != 1 || !warm_cache_shape_valid(cache))
        return false;
    return cache->format_version == host->format_version &&
           cache->architecture == host->architecture &&
           cache->endianness == host->endianness &&
           cache->data_model_bits == host->data_model_bits &&
           cache->page_size == host->page_size &&
           (cache->cpu_feature_floor[0] & ~host->cpu_features[0]) == 0 &&
           (cache->cpu_feature_floor[1] & ~host->cpu_features[1]) == 0;
}

bool zcl_app_warm_cache_admitted_v1(
    const struct zcl_app_warm_cache_v1 *cache,
    const uint8_t checkpoint_root[32],
    const uint8_t expected_attachment_root[32],
    const struct zcl_app_warm_cache_host_v1 *host)
{
    if (!expected_attachment_root ||
        digest_is_zero(expected_attachment_root) ||
        !zcl_app_warm_cache_compatible_v1(cache, host))
        return false;
    uint8_t attachment_root[32];
    return zcl_app_warm_cache_attachment_digest_v1(
               checkpoint_root, cache, attachment_root) &&
           memcmp(attachment_root, expected_attachment_root, 32) == 0;
}

static bool acceptance_shape_valid(
    const struct zcl_app_checkpoint_acceptance_v1 *receipt)
{
    return receipt && receipt->struct_size == sizeof(*receipt) &&
           receipt->schema_version == ZCL_APP_CHECKPOINT_ACCEPTANCE_V1 &&
           !digest_is_zero(receipt->checkpoint_root) &&
           receipt->control_sequence > 0 &&
           !digest_is_zero(receipt->control_event_id) &&
           !digest_is_zero(receipt->control_segment_root) &&
           receipt->accepting_service_id > 0;
}

enum zcl_app_checkpoint_result zcl_app_checkpoint_acceptance_validate_v1(
    const struct zcl_app_checkpoint_acceptance_v1 *receipt,
    const uint8_t expected_checkpoint_root[32])
{
    if (!receipt || !expected_checkpoint_root)
        return ZCL_APP_CHECKPOINT_NULL;
    if (!acceptance_shape_valid(receipt))
        return ZCL_APP_CHECKPOINT_ACCEPTANCE;
    if (memcmp(receipt->checkpoint_root, expected_checkpoint_root, 32) != 0)
        return ZCL_APP_CHECKPOINT_EXPECTED_BINDING;
    return ZCL_APP_CHECKPOINT_OK;
}

bool zcl_app_checkpoint_acceptance_digest_v1(
    const struct zcl_app_checkpoint_acceptance_v1 *receipt,
    uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (!acceptance_shape_valid(receipt))
        return false;
    static const uint8_t domain[] = "zcl.app.checkpoint_acceptance.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    digest_u32(&ctx, receipt->schema_version);
    sha3_256_write(&ctx, receipt->checkpoint_root, 32);
    digest_u64(&ctx, receipt->control_sequence);
    sha3_256_write(&ctx, receipt->control_event_id, 32);
    sha3_256_write(&ctx, receipt->control_segment_root, 32);
    digest_u32(&ctx, receipt->accepting_service_id);
    sha3_256_finalize(&ctx, out);
    return true;
}
