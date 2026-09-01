/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Contract tests for the shadow service catalog, privilege deny rules, graph
 * validation, and canonical service/catalog SHA3 identities. */

#include "test/test_core.h"

#include "config/service_catalog.h"
#include "kernel/service_manifest.h"

#include <string.h>

/* Produced by an independent hashlib.sha3_256 encoder over the documented
 * fixed-width little-endian core zcl.service_manifest.v1 fixture. */
static const uint8_t g_core_manifest_golden_v1[32] = {
    0x8d, 0xeb, 0x87, 0x36, 0xc5, 0x88, 0xa9, 0xab,
    0x22, 0xfb, 0xe0, 0x4f, 0xe4, 0xe1, 0xd7, 0x37,
    0x59, 0xa6, 0xbd, 0xb9, 0xee, 0x48, 0x15, 0x48,
    0xe0, 0x96, 0xf7, 0x82, 0x49, 0x7f, 0xf7, 0x74,
};

static const struct zcl_service_manifest_v1 *catalog_service(
    uint32_t service_id)
{
    size_t count = 0;
    const struct zcl_service_manifest_v1 *catalog =
        zcl_service_catalog_v1(&count);
    for (size_t i = 0; i < count; i++)
        if (catalog[i].service_id == service_id)
            return &catalog[i];
    return NULL;
}

static bool zero_digest(const uint8_t digest[32])
{
    uint8_t seen = 0;
    for (size_t i = 0; i < 32; i++)
        seen |= digest[i];
    return seen == 0;
}

static int test_service_catalog_contract(void)
{
    int failures = 0;
    TEST("service manifest: six-role catalog is valid and shadow-only") {
        size_t count = 0;
        size_t bad_index = 0;
        const struct zcl_service_manifest_v1 *catalog =
            zcl_service_catalog_v1(&count);
        ASSERT(catalog != NULL);
        ASSERT_EQ(count, 6u);
        ASSERT_EQ(zcl_service_catalog_validate_v1(&bad_index),
                  ZCL_SERVICE_MANIFEST_OK);
        ASSERT_EQ(bad_index, SIZE_MAX);
        ASSERT(zcl_service_catalog_shadow_only_v1());
        for (size_t i = 0; i < count; i++) {
            ASSERT_EQ(catalog[i].service_id, i + 1u);
            ASSERT_EQ(catalog[i].enforcement,
                      ZCL_SERVICE_ENFORCEMENT_SHADOW);
            ASSERT(zero_digest(catalog[i].active_generation_root));
            ASSERT(catalog[i].health_deadline_ms <= 15000u);
        }
        ASSERT(catalog_service(ZCL_SERVICE_ID_CORE)->role ==
               ZCL_SERVICE_ROLE_CORE);
        ASSERT(catalog_service(ZCL_SERVICE_ID_WALLET)->trust_class ==
               ZCL_SERVICE_TRUST_KEY_CUSTODY);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_catalog_privilege_boundaries(void)
{
    int failures = 0;
    TEST("service manifest: descriptor classes enforce authority boundaries") {
        const struct zcl_service_manifest_v1 *catalog =
            zcl_service_catalog_v1(NULL);
        for (size_t i = 0; i < 6; i++) {
            for (uint32_t j = 0; j < catalog[i].descriptor_count; j++) {
                uint32_t descriptor_class =
                    catalog[i].descriptors[j].descriptor_class;
                if (descriptor_class ==
                    ZCL_SERVICE_DESCRIPTOR_CONSENSUS_STATE)
                    ASSERT_EQ(catalog[i].role, ZCL_SERVICE_ROLE_CORE);
                if (descriptor_class ==
                    ZCL_SERVICE_DESCRIPTOR_PUBLIC_LISTENER)
                    ASSERT_EQ(catalog[i].role, ZCL_SERVICE_ROLE_EDGE);
                if (descriptor_class ==
                    ZCL_SERVICE_DESCRIPTOR_WALLET_SECRETS)
                    ASSERT_EQ(catalog[i].role, ZCL_SERVICE_ROLE_WALLET);
                if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_APP_STATE)
                    ASSERT_EQ(catalog[i].role, ZCL_SERVICE_ROLE_APPD);
                if (descriptor_class == ZCL_SERVICE_DESCRIPTOR_BUILD_INPUT ||
                    descriptor_class == ZCL_SERVICE_DESCRIPTOR_BUILD_OUTPUT)
                    ASSERT_EQ(catalog[i].role, ZCL_SERVICE_ROLE_BUILDD);
            }
        }

        struct zcl_service_manifest_v1 edge =
            *catalog_service(ZCL_SERVICE_ID_EDGE);
        edge.descriptors[2].descriptor_class =
            ZCL_SERVICE_DESCRIPTOR_WALLET_SECRETS;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&edge),
                  ZCL_SERVICE_MANIFEST_DESCRIPTOR);
        struct zcl_service_manifest_v1 buildd =
            *catalog_service(ZCL_SERVICE_ID_BUILDD);
        buildd.descriptors[2].descriptor_class =
            ZCL_SERVICE_DESCRIPTOR_PUBLIC_LISTENER;
        buildd.descriptors[2].rights = ZCL_SERVICE_DESCRIPTOR_ACCEPT;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&buildd),
                  ZCL_SERVICE_MANIFEST_DESCRIPTOR);
        edge = *catalog_service(ZCL_SERVICE_ID_EDGE);
        edge.descriptors[1].rights = ZCL_SERVICE_DESCRIPTOR_READ |
                                      ZCL_SERVICE_DESCRIPTOR_WRITE;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&edge),
                  ZCL_SERVICE_MANIFEST_DESCRIPTOR);
        buildd = *catalog_service(ZCL_SERVICE_ID_BUILDD);
        buildd.descriptors[2].rights = ZCL_SERVICE_DESCRIPTOR_WRITE;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&buildd),
                  ZCL_SERVICE_MANIFEST_DESCRIPTOR);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_catalog_operation_registry(void)
{
    int failures = 0;
    TEST("service manifest: peer-local operation registry fails closed") {
        size_t count = 0;
        const struct zcl_service_manifest_v1 *catalog =
            zcl_service_catalog_v1(&count);
        for (size_t i = 0; i < count; i++) {
            for (uint32_t j = 0; j < catalog[i].ipc_grant_count; j++) {
                ASSERT(zcl_service_catalog_ipc_grant_known_v1(
                    catalog[i].service_id,
                    catalog[i].ipc_grants[j].peer_service_id,
                    catalog[i].ipc_grants[j].operation_id));
            }
        }
        ASSERT(!zcl_service_catalog_ipc_grant_known_v1(
            ZCL_SERVICE_ID_EDGE, ZCL_SERVICE_ID_CORE, 99));
        ASSERT(!zcl_service_catalog_ipc_grant_known_v1(
            ZCL_SERVICE_ID_EDGE, ZCL_SERVICE_ID_WALLET,
            ZCL_WALLET_OPERATION_INTENT_V1));
        ASSERT(!zcl_service_catalog_ipc_grant_known_v1(
            ZCL_SERVICE_ID_CORE, ZCL_SERVICE_ID_EDGE,
            ZCL_EDGE_OPERATION_APP_PUBLISH_V1));
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_manifest_generation_and_restart(void)
{
    int failures = 0;
    TEST("service manifest: enforcement and restart budgets fail closed") {
        struct zcl_service_manifest_v1 core =
            *catalog_service(ZCL_SERVICE_ID_CORE);
        core.enforcement = ZCL_SERVICE_ENFORCEMENT_ACTIVE;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&core),
                  ZCL_SERVICE_MANIFEST_GENERATION);
        memset(core.active_generation_root, 0x5a,
               sizeof(core.active_generation_root));
        ASSERT_EQ(zcl_service_manifest_validate_v1(&core),
                  ZCL_SERVICE_MANIFEST_OK);
        core.enforcement = ZCL_SERVICE_ENFORCEMENT_SHADOW;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&core),
                  ZCL_SERVICE_MANIFEST_GENERATION);

        core = *catalog_service(ZCL_SERVICE_ID_CORE);
        core.restart.max_restarts = 0;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&core),
                  ZCL_SERVICE_MANIFEST_RESTART_BUDGET);
        core = *catalog_service(ZCL_SERVICE_ID_INIT);
        core.restart.window_ms = 300000;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&core),
                  ZCL_SERVICE_MANIFEST_RESTART_BUDGET);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_catalog_graph_failures(void)
{
    int failures = 0;
    TEST("service manifest: missing references and cycles are typed blockers") {
        size_t count = 0;
        const struct zcl_service_manifest_v1 *catalog =
            zcl_service_catalog_v1(&count);
        struct zcl_service_manifest_v1 copy[6];
        ASSERT_EQ(count, sizeof(copy) / sizeof(copy[0]));
        memcpy(copy, catalog, sizeof(copy));
        copy[1].dependencies[0] = 99;
        size_t bad_index = SIZE_MAX;
        ASSERT_EQ(zcl_service_manifest_catalog_validate_v1(
                      copy, count, &bad_index),
                  ZCL_SERVICE_MANIFEST_CATALOG_REFERENCE);
        ASSERT_EQ(bad_index, 1u);

        memcpy(copy, catalog, sizeof(copy));
        copy[1].dependencies[0] = ZCL_SERVICE_ID_EDGE;
        ASSERT_EQ(zcl_service_manifest_catalog_validate_v1(
                      copy, count, &bad_index),
                  ZCL_SERVICE_MANIFEST_CATALOG_CYCLE);

        memcpy(copy, catalog, sizeof(copy));
        memcpy(copy[4].name, copy[3].name, sizeof(copy[4].name));
        ASSERT_EQ(zcl_service_manifest_catalog_validate_v1(
                      copy, count, &bad_index),
                  ZCL_SERVICE_MANIFEST_CATALOG_ORDER);

        memcpy(copy, catalog, sizeof(copy));
        copy[2].dependencies[0] = ZCL_SERVICE_ID_CORE;
        copy[2].dependencies[1] = ZCL_SERVICE_ID_INIT;
        ASSERT_EQ(zcl_service_manifest_catalog_validate_v1(
                      copy, count, &bad_index),
                  ZCL_SERVICE_MANIFEST_DEPENDENCY);

        memcpy(copy, catalog, sizeof(copy));
        copy[2].readiness.source_service_id = ZCL_SERVICE_ID_WALLET;
        ASSERT_EQ(zcl_service_manifest_catalog_validate_v1(
                      copy, count, &bad_index),
                  ZCL_SERVICE_MANIFEST_CATALOG_REFERENCE);
        ASSERT_EQ(bad_index, 2u);

        struct zcl_service_manifest_v1 init =
            *catalog_service(ZCL_SERVICE_ID_INIT);
        init.readiness.source_service_id = ZCL_SERVICE_ID_CORE;
        ASSERT_EQ(zcl_service_manifest_validate_v1(&init),
                  ZCL_SERVICE_MANIFEST_READINESS);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_manifest_canonical_digest(void)
{
    int failures = 0;
    TEST("service manifest: canonical SHA3 excludes padding and binds policy") {
        uint8_t catalog_root_a[32];
        uint8_t catalog_root_b[32];
        ASSERT(zcl_service_catalog_digest_v1(catalog_root_a));
        ASSERT(zcl_service_catalog_digest_v1(catalog_root_b));
        ASSERT(!zero_digest(catalog_root_a));
        ASSERT(memcmp(catalog_root_a, catalog_root_b, 32) == 0);

        struct zcl_service_manifest_v1 core =
            *catalog_service(ZCL_SERVICE_ID_CORE);
        uint8_t root_a[32];
        uint8_t root_b[32];
        ASSERT(zcl_service_manifest_digest_v1(&core, root_a));
        ASSERT(memcmp(root_a, g_core_manifest_golden_v1, 32) == 0);
        core.name[5] = 'x';
        ASSERT(zcl_service_manifest_digest_v1(&core, root_b));
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        core = *catalog_service(ZCL_SERVICE_ID_CORE);
        core.resources.memory_bytes++;
        ASSERT(zcl_service_manifest_digest_v1(&core, root_b));
        ASSERT(memcmp(root_a, root_b, 32) != 0);

        core.schema_version = 99;
        memset(root_b, 0xa5, sizeof(root_b));
        ASSERT(!zcl_service_manifest_digest_v1(&core, root_b));
        ASSERT(zero_digest(root_b));
        PASS();
    } _test_next:;
    return failures;
}

int test_service_manifest(void)
{
    int failures = 0;
    failures += test_service_catalog_contract();
    failures += test_service_catalog_privilege_boundaries();
    failures += test_service_catalog_operation_registry();
    failures += test_service_manifest_generation_and_restart();
    failures += test_service_catalog_graph_failures();
    failures += test_service_manifest_canonical_digest();
    return failures;
}
