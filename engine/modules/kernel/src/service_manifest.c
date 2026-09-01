/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure validation and canonical SHA3 identity for service-manifest policy.
 * This module performs no launch, restart, descriptor, or IPC operation. */

#include "kernel/service_manifest.h"

#include "crypto/sha3.h"

#include <limits.h>
#include <string.h>

static bool digest_is_zero(const uint8_t digest[32])
{
    uint8_t seen = 0;
    for (size_t i = 0; i < 32; i++)
        seen |= digest[i];
    return seen == 0;
}

static bool canonical_name(const char *text, size_t capacity, bool dotted)
{
    const char *end = memchr(text, '\0', capacity);
    if (!end || end == text || text[0] < 'a' || text[0] > 'z')
        return false;
    for (const char *p = text; p < end; p++) {
        bool lower = *p >= 'a' && *p <= 'z';
        bool digit = *p >= '0' && *p <= '9';
        bool separator = *p == '_' || *p == '-';
        if (dotted)
            separator = separator || *p == '.';
        if (!lower && !digit && !separator)
            return false;
    }
    return true;
}

static bool valid_role_trust(uint32_t role, uint32_t trust)
{
    static const uint32_t expected[] = {
        [ZCL_SERVICE_ROLE_INIT] = ZCL_SERVICE_TRUST_SUPERVISOR,
        [ZCL_SERVICE_ROLE_CORE] = ZCL_SERVICE_TRUST_CONSENSUS,
        [ZCL_SERVICE_ROLE_EDGE] = ZCL_SERVICE_TRUST_PUBLIC_EDGE,
        [ZCL_SERVICE_ROLE_WALLET] = ZCL_SERVICE_TRUST_KEY_CUSTODY,
        [ZCL_SERVICE_ROLE_APPD] = ZCL_SERVICE_TRUST_APP_BROKER,
        [ZCL_SERVICE_ROLE_BUILDD] = ZCL_SERVICE_TRUST_UNTRUSTED_BUILD,
    };
    return role >= ZCL_SERVICE_ROLE_INIT &&
           role <= ZCL_SERVICE_ROLE_BUILDD && expected[role] == trust;
}

static bool descriptor_allowed(uint32_t role, uint32_t descriptor_class,
                               uint32_t rights)
{
    const uint32_t all_rights = ZCL_SERVICE_DESCRIPTOR_READ |
                                ZCL_SERVICE_DESCRIPTOR_WRITE |
                                ZCL_SERVICE_DESCRIPTOR_ACCEPT;
    if (descriptor_class <= ZCL_SERVICE_DESCRIPTOR_INVALID ||
        descriptor_class > ZCL_SERVICE_DESCRIPTOR_BUILD_OUTPUT ||
        rights == 0 || (rights & ~all_rights) != 0)
        return false;
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_CONSENSUS_STATE)
        return role == ZCL_SERVICE_ROLE_CORE &&
               rights == (ZCL_SERVICE_DESCRIPTOR_READ |
                          ZCL_SERVICE_DESCRIPTOR_WRITE);
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_PUBLIC_LISTENER)
        return role == ZCL_SERVICE_ROLE_EDGE &&
               rights == ZCL_SERVICE_DESCRIPTOR_ACCEPT;
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_CHAIN_LISTENER)
        return role == ZCL_SERVICE_ROLE_CORE &&
               rights == ZCL_SERVICE_DESCRIPTOR_ACCEPT;
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_WALLET_SECRETS)
        return role == ZCL_SERVICE_ROLE_WALLET &&
               rights == (ZCL_SERVICE_DESCRIPTOR_READ |
                          ZCL_SERVICE_DESCRIPTOR_WRITE);
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_APP_STATE)
        return role == ZCL_SERVICE_ROLE_APPD &&
               rights == (ZCL_SERVICE_DESCRIPTOR_READ |
                          ZCL_SERVICE_DESCRIPTOR_WRITE);
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_BUILD_INPUT)
        return role == ZCL_SERVICE_ROLE_BUILDD &&
               rights == ZCL_SERVICE_DESCRIPTOR_READ;
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_BUILD_OUTPUT)
        return role == ZCL_SERVICE_ROLE_BUILDD &&
               rights == ZCL_SERVICE_DESCRIPTOR_WRITE;
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_PRIVATE_CAS)
        return role == ZCL_SERVICE_ROLE_APPD &&
               rights == (ZCL_SERVICE_DESCRIPTOR_READ |
                          ZCL_SERVICE_DESCRIPTOR_WRITE);
    if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_CONTROL)
        return rights == (ZCL_SERVICE_DESCRIPTOR_READ |
                          ZCL_SERVICE_DESCRIPTOR_WRITE);
    return descriptor_class == ZCL_SERVICE_DESCRIPTOR_LOG &&
           rights == ZCL_SERVICE_DESCRIPTOR_WRITE;
}

static bool strictly_sorted_u32(const uint32_t *values, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        if (values[i] == 0 || (i > 0 && values[i - 1] >= values[i]))
            return false;
    }
    return true;
}

static bool ipc_grants_sorted(
    const struct zcl_service_ipc_grant_v1 *grants, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        if (grants[i].peer_service_id == 0 || grants[i].operation_id == 0)
            return false;
        if (i > 0 &&
            (grants[i - 1].peer_service_id > grants[i].peer_service_id ||
             (grants[i - 1].peer_service_id == grants[i].peer_service_id &&
              grants[i - 1].operation_id >= grants[i].operation_id)))
            return false;
    }
    return true;
}

static bool descriptors_sorted(
    const struct zcl_service_manifest_v1 *manifest)
{
    for (uint32_t i = 0; i < manifest->descriptor_count; i++) {
        const struct zcl_service_descriptor_grant_v1 *grant =
            &manifest->descriptors[i];
        if (grant->capability_id == 0 ||
            (i > 0 && manifest->descriptors[i - 1].capability_id >=
                          grant->capability_id) ||
            !descriptor_allowed(manifest->role, grant->descriptor_class,
                                grant->rights))
            return false;
    }
    return true;
}

enum zcl_service_manifest_result zcl_service_manifest_validate_v1(
    const struct zcl_service_manifest_v1 *manifest)
{
    if (!manifest)
        return ZCL_SERVICE_MANIFEST_NULL;
    if (manifest->struct_size != sizeof(*manifest) ||
        manifest->schema_version != ZCL_SERVICE_MANIFEST_V1)
        return ZCL_SERVICE_MANIFEST_SCHEMA;
    if (manifest->service_id == 0 ||
        !canonical_name(manifest->name, sizeof(manifest->name), false))
        return ZCL_SERVICE_MANIFEST_IDENTITY;
    if (!valid_role_trust(manifest->role, manifest->trust_class))
        return ZCL_SERVICE_MANIFEST_ROLE_TRUST;
    if (manifest->enforcement != ZCL_SERVICE_ENFORCEMENT_SHADOW &&
        manifest->enforcement != ZCL_SERVICE_ENFORCEMENT_ACTIVE)
        return ZCL_SERVICE_MANIFEST_ENFORCEMENT;
    if (manifest->dependency_count > ZCL_SERVICE_DEPENDENCY_MAX ||
        !strictly_sorted_u32(manifest->dependencies,
                             manifest->dependency_count))
        return ZCL_SERVICE_MANIFEST_DEPENDENCY;
    if (manifest->role == ZCL_SERVICE_ROLE_INIT &&
        manifest->dependency_count != 0)
        return ZCL_SERVICE_MANIFEST_DEPENDENCY;
    for (uint32_t i = 0; i < manifest->dependency_count; i++)
        if (manifest->dependencies[i] == manifest->service_id)
            return ZCL_SERVICE_MANIFEST_DEPENDENCY;

    const struct zcl_service_readiness_witness_v1 *ready =
        &manifest->readiness;
    if (ready->kind < ZCL_SERVICE_READINESS_SELF_TEST ||
        ready->kind > ZCL_SERVICE_READINESS_DURABLE_PROGRESS ||
        ready->source_service_id == 0 || ready->witness_schema_id == 0 ||
        ready->max_age_ms == 0)
        return ZCL_SERVICE_MANIFEST_READINESS;
    if ((ready->kind == ZCL_SERVICE_READINESS_SELF_TEST ||
         ready->kind == ZCL_SERVICE_READINESS_DURABLE_PROGRESS) &&
        ready->source_service_id != manifest->service_id)
        return ZCL_SERVICE_MANIFEST_READINESS;
    if (ready->kind == ZCL_SERVICE_READINESS_SERVICE_READY &&
        ready->source_service_id == manifest->service_id)
        return ZCL_SERVICE_MANIFEST_READINESS;
    if (manifest->ipc_grant_count > ZCL_SERVICE_IPC_GRANT_MAX ||
        !ipc_grants_sorted(manifest->ipc_grants,
                           manifest->ipc_grant_count))
        return ZCL_SERVICE_MANIFEST_IPC_GRANT;
    for (uint32_t i = 0; i < manifest->ipc_grant_count; i++)
        if (manifest->ipc_grants[i].peer_service_id == manifest->service_id)
            return ZCL_SERVICE_MANIFEST_IPC_GRANT;
    if (manifest->descriptor_count > ZCL_SERVICE_DESCRIPTOR_MAX ||
        !descriptors_sorted(manifest))
        return ZCL_SERVICE_MANIFEST_DESCRIPTOR;

    const struct zcl_service_resource_budget_v1 *resource =
        &manifest->resources;
    if (resource->cpu_quota_us == 0 || resource->cpu_period_us == 0 ||
        resource->memory_bytes == 0 || resource->storage_bytes == 0 ||
        resource->process_limit == 0 || resource->process_limit > 4096u ||
        resource->open_file_limit == 0 ||
        resource->open_file_limit > (1u << 20))
        return ZCL_SERVICE_MANIFEST_RESOURCE_BUDGET;

    const struct zcl_service_restart_budget_v1 *restart = &manifest->restart;
    if (restart->policy > ZCL_SERVICE_RESTART_PERMANENT)
        return ZCL_SERVICE_MANIFEST_RESTART_BUDGET;
    if (restart->policy == ZCL_SERVICE_RESTART_TEMPORARY) {
        if (restart->max_restarts != 0 || restart->window_ms != 0)
            return ZCL_SERVICE_MANIFEST_RESTART_BUDGET;
    } else if (restart->max_restarts == 0 || restart->max_restarts > 100u ||
               restart->window_ms == 0 || restart->window_ms > 86400000u) {
        return ZCL_SERVICE_MANIFEST_RESTART_BUDGET;
    }

    if (!canonical_name(manifest->state_schema,
                        sizeof(manifest->state_schema), true))
        return ZCL_SERVICE_MANIFEST_STATE_SCHEMA;
    bool zero_generation = digest_is_zero(manifest->active_generation_root);
    if ((manifest->enforcement == ZCL_SERVICE_ENFORCEMENT_ACTIVE) ==
        zero_generation)
        return ZCL_SERVICE_MANIFEST_GENERATION;
    if (manifest->health_deadline_ms == 0 ||
        manifest->health_deadline_ms > 86400000u ||
        ready->max_age_ms > manifest->health_deadline_ms ||
        manifest->durable_progress_schema_id == 0)
        return ZCL_SERVICE_MANIFEST_HEALTH;
    return ZCL_SERVICE_MANIFEST_OK;
}

static size_t find_service(const struct zcl_service_manifest_v1 *manifests,
                           size_t count, uint32_t service_id)
{
    size_t low = 0;
    size_t high = count;
    while (low < high) {
        size_t mid = low + (high - low) / 2u;
        if (manifests[mid].service_id < service_id)
            low = mid + 1u;
        else
            high = mid;
    }
    return low < count && manifests[low].service_id == service_id
               ? low : SIZE_MAX;
}

static bool visit_service(const struct zcl_service_manifest_v1 *manifests,
                          size_t count, size_t index, uint8_t marks[64])
{
    if (marks[index] == 1)
        return false;
    if (marks[index] == 2)
        return true;
    marks[index] = 1;
    for (uint32_t i = 0; i < manifests[index].dependency_count; i++) {
        size_t dependency = find_service(manifests, count,
                                         manifests[index].dependencies[i]);
        if (dependency == SIZE_MAX ||
            !visit_service(manifests, count, dependency, marks))
            return false;
    }
    marks[index] = 2;
    return true;
}

enum zcl_service_manifest_result zcl_service_manifest_catalog_validate_v1(
    const struct zcl_service_manifest_v1 *manifests,
    size_t count,
    size_t *bad_index)
{
    if (bad_index)
        *bad_index = SIZE_MAX;
    if (!manifests || count == 0 || count > ZCL_SERVICE_CATALOG_MAX)
        return ZCL_SERVICE_MANIFEST_NULL;
    for (size_t i = 0; i < count; i++) {
        enum zcl_service_manifest_result result =
            zcl_service_manifest_validate_v1(&manifests[i]);
        if (result != ZCL_SERVICE_MANIFEST_OK) {
            if (bad_index)
                *bad_index = i;
            return result;
        }
        if (i > 0 && manifests[i - 1].service_id >= manifests[i].service_id) {
            if (bad_index)
                *bad_index = i;
            return ZCL_SERVICE_MANIFEST_CATALOG_ORDER;
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(manifests[j].name, manifests[i].name) == 0) {
                if (bad_index)
                    *bad_index = i;
                return ZCL_SERVICE_MANIFEST_CATALOG_ORDER;
            }
        }
    }
    for (size_t i = 0; i < count; i++) {
        if (find_service(manifests, count,
                         manifests[i].readiness.source_service_id) ==
            SIZE_MAX) {
            if (bad_index)
                *bad_index = i;
            return ZCL_SERVICE_MANIFEST_CATALOG_REFERENCE;
        }
        if (manifests[i].readiness.kind ==
            ZCL_SERVICE_READINESS_SERVICE_READY) {
            bool direct_dependency = false;
            for (uint32_t j = 0; j < manifests[i].dependency_count; j++)
                if (manifests[i].dependencies[j] ==
                    manifests[i].readiness.source_service_id)
                    direct_dependency = true;
            if (!direct_dependency) {
                if (bad_index)
                    *bad_index = i;
                return ZCL_SERVICE_MANIFEST_CATALOG_REFERENCE;
            }
        }
        for (uint32_t j = 0; j < manifests[i].dependency_count; j++) {
            if (find_service(manifests, count,
                             manifests[i].dependencies[j]) == SIZE_MAX) {
                if (bad_index)
                    *bad_index = i;
                return ZCL_SERVICE_MANIFEST_CATALOG_REFERENCE;
            }
        }
        for (uint32_t j = 0; j < manifests[i].ipc_grant_count; j++) {
            if (find_service(manifests, count,
                             manifests[i].ipc_grants[j].peer_service_id) ==
                SIZE_MAX) {
                if (bad_index)
                    *bad_index = i;
                return ZCL_SERVICE_MANIFEST_CATALOG_REFERENCE;
            }
        }
    }
    uint8_t marks[ZCL_SERVICE_CATALOG_MAX] = {0};
    for (size_t i = 0; i < count; i++) {
        if (!visit_service(manifests, count, i, marks)) {
            if (bad_index)
                *bad_index = i;
            return ZCL_SERVICE_MANIFEST_CATALOG_CYCLE;
        }
    }
    return ZCL_SERVICE_MANIFEST_OK;
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

static void digest_manifest_fields(struct sha3_256_ctx *ctx,
                                   const struct zcl_service_manifest_v1 *m)
{
    digest_u32(ctx, m->schema_version);
    digest_u32(ctx, m->service_id);
    digest_text(ctx, m->name, sizeof(m->name));
    digest_u32(ctx, m->role);
    digest_u32(ctx, m->trust_class);
    digest_u32(ctx, m->enforcement);
    digest_u32(ctx, m->dependency_count);
    for (uint32_t i = 0; i < m->dependency_count; i++)
        digest_u32(ctx, m->dependencies[i]);
    digest_u32(ctx, m->readiness.kind);
    digest_u32(ctx, m->readiness.source_service_id);
    digest_u32(ctx, m->readiness.witness_schema_id);
    digest_u64(ctx, m->readiness.max_age_ms);
    digest_u32(ctx, m->ipc_grant_count);
    for (uint32_t i = 0; i < m->ipc_grant_count; i++) {
        digest_u32(ctx, m->ipc_grants[i].peer_service_id);
        digest_u32(ctx, m->ipc_grants[i].operation_id);
    }
    digest_u32(ctx, m->descriptor_count);
    for (uint32_t i = 0; i < m->descriptor_count; i++) {
        digest_u32(ctx, m->descriptors[i].capability_id);
        digest_u32(ctx, m->descriptors[i].descriptor_class);
        digest_u32(ctx, m->descriptors[i].rights);
    }
    digest_u64(ctx, m->resources.cpu_quota_us);
    digest_u64(ctx, m->resources.cpu_period_us);
    digest_u64(ctx, m->resources.memory_bytes);
    digest_u64(ctx, m->resources.storage_bytes);
    digest_u32(ctx, m->resources.process_limit);
    digest_u32(ctx, m->resources.open_file_limit);
    digest_u32(ctx, m->restart.policy);
    digest_u32(ctx, m->restart.max_restarts);
    digest_u64(ctx, m->restart.window_ms);
    digest_text(ctx, m->state_schema, sizeof(m->state_schema));
    sha3_256_write(ctx, m->active_generation_root, 32);
    digest_u64(ctx, m->health_deadline_ms);
    digest_u32(ctx, m->durable_progress_schema_id);
}

bool zcl_service_manifest_digest_v1(
    const struct zcl_service_manifest_v1 *manifest,
    uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (zcl_service_manifest_validate_v1(manifest) !=
        ZCL_SERVICE_MANIFEST_OK)
        return false;
    static const uint8_t domain[] = "zcl.service_manifest.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    digest_manifest_fields(&ctx, manifest);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool zcl_service_manifest_catalog_digest_v1(
    const struct zcl_service_manifest_v1 *manifests,
    size_t count,
    uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (zcl_service_manifest_catalog_validate_v1(manifests, count, NULL) !=
        ZCL_SERVICE_MANIFEST_OK)
        return false;
    static const uint8_t domain[] = "zcl.service_catalog.v2";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    digest_u32(&ctx, (uint32_t)count);
    for (size_t i = 0; i < count; i++) {
        uint8_t digest[32];
        if (!zcl_service_manifest_digest_v1(&manifests[i], digest)) {
            memset(out, 0, 32);
            return false;
        }
        sha3_256_write(&ctx, digest, sizeof(digest));
    }
    sha3_256_finalize(&ctx, out);
    return true;
}
