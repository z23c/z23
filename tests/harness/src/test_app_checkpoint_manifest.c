/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial tests for private App checkpoint identity, exact admission,
 * fork quarantine, chunk layout, warm-cache detachment, and journal receipts. */

#include "test/test_core.h"

#include "framework/app_checkpoint.h"

#include <string.h>

static const uint8_t g_full_chunk[ZCL_APP_STATE_CHUNK_BYTES_V1];
static const uint8_t g_tail_chunk[17] = { 1, 2, 3 };
/* Produced by an independent hashlib.sha3_256 encoder over the documented
 * fixed-width little-endian zcl.app.checkpoint.v1 fixture. */
static const uint8_t g_checkpoint_golden_v1[32] = {
    0x99, 0x5b, 0xb5, 0xd1, 0x99, 0x24, 0x6e, 0x6c,
    0xa7, 0xa9, 0x7d, 0x58, 0xd6, 0xf3, 0x1a, 0x4c,
    0x07, 0x19, 0xd0, 0x0a, 0x07, 0x92, 0xdf, 0xae,
    0xc2, 0x0d, 0x1a, 0xb9, 0x62, 0x14, 0x0d, 0xa9,
};

static void fill_root(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static bool root_is_zero(const uint8_t root[32])
{
    uint8_t seen = 0;
    for (size_t i = 0; i < 32; i++)
        seen |= root[i];
    return seen == 0;
}

static void make_chunks(struct zcl_app_state_chunk_v1 chunks[2])
{
    memset(chunks, 0, sizeof(*chunks) * 2u);
    chunks[0].index = 0;
    chunks[0].length = ZCL_APP_STATE_CHUNK_BYTES_V1;
    chunks[0].offset = 0;
    (void)zcl_app_state_chunk_digest_v1(
        g_full_chunk, sizeof(g_full_chunk), chunks[0].digest);
    chunks[1].index = 1;
    chunks[1].length = sizeof(g_tail_chunk);
    chunks[1].offset = ZCL_APP_STATE_CHUNK_BYTES_V1;
    (void)zcl_app_state_chunk_digest_v1(
        g_tail_chunk, sizeof(g_tail_chunk), chunks[1].digest);
}

static void empty_cursor(struct zcl_app_checkpoint_cursor_v1 *cursor,
                         uint32_t component)
{
    memset(cursor, 0, sizeof(*cursor));
    (void)zcl_app_checkpoint_empty_component_root_v1(component, cursor->root);
}

static struct zcl_app_checkpoint_manifest_v1 valid_manifest(
    const struct zcl_app_state_chunk_v1 chunks[2])
{
    struct zcl_app_checkpoint_manifest_v1 manifest = {0};
    manifest.struct_size = sizeof(manifest);
    manifest.schema_version = ZCL_APP_CHECKPOINT_V1;
    memcpy(manifest.app_id, "blog", 5);
    fill_root(manifest.instance_id, 0x11);
    fill_root(manifest.publisher_root, 0x12);
    fill_root(manifest.package_root, 0x13);
    fill_root(manifest.artifact_root, 0x14);
    manifest.activation_generation = 7;
    fill_root(manifest.activation_generation_root, 0x15);
    manifest.state_generation = 19;
    fill_root(manifest.state_generation_root, 0x16);
    manifest.grant_revision = 23;
    fill_root(manifest.grant_root, 0x17);
    manifest.storage_format = ZCL_APP_CHECKPOINT_STORAGE_SQLITE3;
    manifest.storage_class = ZCL_APP_CHECKPOINT_CLASS_PRIVATE_LOCAL;
    manifest.app_schema_version = 3;
    manifest.sdk_abi = 2;
    manifest.logical_root_codec = ZCL_APP_LOGICAL_ROOT_CODEC_V1;
    fill_root(manifest.migration_lineage_root, 0x18);
    fill_root(manifest.logical_state_root, 0x19);
    empty_cursor(&manifest.events, ZCL_APP_CHECKPOINT_COMPONENT_EVENTS);
    empty_cursor(&manifest.outbox, ZCL_APP_CHECKPOINT_COMPONENT_OUTBOX);
    empty_cursor(&manifest.subscriptions,
                 ZCL_APP_CHECKPOINT_COMPONENT_SUBSCRIPTIONS);
    empty_cursor(&manifest.routes, ZCL_APP_CHECKPOINT_COMPONENT_ROUTES);
    empty_cursor(&manifest.jobs, ZCL_APP_CHECKPOINT_COMPONENT_JOBS);
    manifest.chunk_size = ZCL_APP_STATE_CHUNK_BYTES_V1;
    manifest.chunk_count = 2;
    manifest.total_bytes = ZCL_APP_STATE_CHUNK_BYTES_V1 +
                           sizeof(g_tail_chunk);
    (void)zcl_app_checkpoint_image_root_v1(
        manifest.chunk_size, manifest.total_bytes, chunks, 2,
        manifest.sqlite_image_root);
    manifest.creation_cause = ZCL_APP_CHECKPOINT_CAUSE_INITIAL;
    manifest.state_origin = ZCL_APP_CHECKPOINT_ORIGIN_LIVE;
    manifest.outbox_mode = ZCL_APP_CHECKPOINT_OUTBOX_CONTROLLED;
    return manifest;
}

static struct zcl_app_checkpoint_expected_v1 expected_binding(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 chunks[2],
    uint32_t admission)
{
    struct zcl_app_checkpoint_expected_v1 expected = {0};
    expected.struct_size = sizeof(expected);
    expected.admission = admission;
    (void)zcl_app_checkpoint_digest_v1(
        manifest, chunks, 2, expected.checkpoint_root);
    expected.accepting_service_id = 5;
    expected.control_sequence = 42;
    fill_root(expected.control_event_id, 0xa1);
    fill_root(expected.control_segment_root, 0xa2);
    if (manifest->has_parent == 0)
        fill_root(expected.instance_creation_receipt_root, 0xa4);
    if (admission == ZCL_APP_CHECKPOINT_ADMISSION_ISOLATED_SCENARIO) {
        fill_root(expected.scenario_principal_root, 0xb1);
        expected.scenario_grant_revision = 1;
        fill_root(expected.scenario_grant_root, 0xb2);
        fill_root(expected.attenuation_receipt_root, 0xb3);
    }
    memcpy(expected.app_id, manifest->app_id, sizeof(expected.app_id));
    memcpy(expected.instance_id, manifest->instance_id, 32);
    memcpy(expected.publisher_root, manifest->publisher_root, 32);
    memcpy(expected.package_root, manifest->package_root, 32);
    memcpy(expected.artifact_root, manifest->artifact_root, 32);
    expected.activation_generation = manifest->activation_generation;
    memcpy(expected.activation_generation_root,
           manifest->activation_generation_root, 32);
    expected.state_generation = manifest->state_generation;
    memcpy(expected.state_generation_root,
           manifest->state_generation_root, 32);
    expected.grant_revision = manifest->grant_revision;
    memcpy(expected.grant_root, manifest->grant_root, 32);
    expected.app_schema_version = manifest->app_schema_version;
    expected.sdk_abi = manifest->sdk_abi;
    expected.logical_root_codec = manifest->logical_root_codec;
    memcpy(expected.migration_lineage_root,
           manifest->migration_lineage_root, 32);
    return expected;
}

static struct zcl_app_checkpoint_acceptance_v1 expected_acceptance(
    const struct zcl_app_checkpoint_expected_v1 *expected)
{
    struct zcl_app_checkpoint_acceptance_v1 acceptance = {
        .struct_size = sizeof(acceptance),
        .schema_version = ZCL_APP_CHECKPOINT_ACCEPTANCE_V1,
        .control_sequence = expected->control_sequence,
        .accepting_service_id = expected->accepting_service_id,
    };
    memcpy(acceptance.checkpoint_root, expected->checkpoint_root, 32);
    memcpy(acceptance.control_event_id, expected->control_event_id, 32);
    memcpy(acceptance.control_segment_root,
           expected->control_segment_root, 32);
    return acceptance;
}

static void bind_expected_parent(
    struct zcl_app_checkpoint_expected_v1 *expected,
    const struct zcl_app_checkpoint_acceptance_v1 *parent_acceptance)
{
    expected->control_sequence = parent_acceptance->control_sequence + 1u;
    fill_root(expected->control_event_id, 0xa3);
    (void)zcl_app_checkpoint_acceptance_digest_v1(
        parent_acceptance, expected->parent_acceptance_receipt_root);
}

static int test_checkpoint_valid_and_canonical(void)
{
    int failures = 0;
    TEST("app checkpoint: valid private state has a deterministic root") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 manifest =
            valid_manifest(chunks);
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);
        struct zcl_app_checkpoint_expected_v1 expected = expected_binding(
            &manifest, chunks,
            ZCL_APP_CHECKPOINT_ADMISSION_PRODUCTION_SWITCH);
        struct zcl_app_checkpoint_acceptance_v1 acceptance =
            expected_acceptance(&expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_OK);
        manifest.state_generation_root[0] ^= 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_EXPECTED_BINDING);
        manifest.state_generation_root[0] ^= 1;
        uint8_t root_a[32];
        uint8_t root_b[32];
        ASSERT(zcl_app_checkpoint_digest_v1(&manifest, chunks, 2, root_a));
        ASSERT(zcl_app_checkpoint_digest_v1(&manifest, chunks, 2, root_b));
        ASSERT(!root_is_zero(root_a));
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        ASSERT(memcmp(root_a, g_checkpoint_golden_v1, 32) == 0);
        manifest.grant_revision++;
        ASSERT(zcl_app_checkpoint_digest_v1(&manifest, chunks, 2, root_b));
        ASSERT(memcmp(root_a, root_b, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_checkpoint_chunk_layout(void)
{
    int failures = 0;
    TEST("app checkpoint: chunk gaps, overlaps, and substitutions fail closed") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 manifest =
            valid_manifest(chunks);
        chunks[1].offset--;
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_CHUNK_LAYOUT);
        make_chunks(chunks);
        chunks[1].length++;
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_CHUNK_LAYOUT);
        make_chunks(chunks);
        chunks[1].digest[0] ^= 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_IMAGE_ROOT);
        make_chunks(chunks);
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 1),
                  ZCL_APP_CHECKPOINT_CHUNK_LAYOUT);
        manifest.chunk_size = 4096;
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_CHUNK_LAYOUT);
        PASS();
    } _test_next:;
    return failures;
}

static int test_state_chunk_domain(void)
{
    int failures = 0;
    TEST("app checkpoint: state chunks are bounded and domain separated") {
        const uint8_t one[] = { 0x42 };
        const uint8_t two[] = { 0x42, 0x00 };
        uint8_t root_one[32];
        uint8_t root_two[32];
        ASSERT(zcl_app_state_chunk_digest_v1(one, sizeof(one), root_one));
        ASSERT(zcl_app_state_chunk_digest_v1(two, sizeof(two), root_two));
        ASSERT(memcmp(root_one, root_two, 32) != 0);
        memset(root_two, 0xa5, sizeof(root_two));
        ASSERT(!zcl_app_state_chunk_digest_v1(NULL, 1, root_two));
        ASSERT(root_is_zero(root_two));
        ASSERT(!zcl_app_state_chunk_digest_v1(one, 0, root_two));
        ASSERT(!zcl_app_state_chunk_digest_v1(
            g_full_chunk, ZCL_APP_STATE_CHUNK_BYTES_V1 + 1u, root_two));
        PASS();
    } _test_next:;
    return failures;
}

static int test_checkpoint_exact_binding(void)
{
    int failures = 0;
    TEST("app checkpoint: stale package, state, and grant bindings are rejected") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 manifest =
            valid_manifest(chunks);
        struct zcl_app_checkpoint_expected_v1 expected = expected_binding(
            &manifest, chunks,
            ZCL_APP_CHECKPOINT_ADMISSION_RESTORE_SOURCE);
        struct zcl_app_checkpoint_acceptance_v1 acceptance =
            expected_acceptance(&expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, NULL, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_EXPECTED_BINDING);
        acceptance.control_event_id[0] ^= 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_ACCEPTANCE);
        acceptance.control_event_id[0] ^= 1;
        expected.package_root[0] ^= 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_EXPECTED_BINDING);
        expected = expected_binding(
            &manifest, chunks,
            ZCL_APP_CHECKPOINT_ADMISSION_RESTORE_SOURCE);
        acceptance = expected_acceptance(&expected);
        memset(expected.instance_creation_receipt_root, 0, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_ADMISSION);
        expected = expected_binding(
            &manifest, chunks,
            ZCL_APP_CHECKPOINT_ADMISSION_RESTORE_SOURCE);
        acceptance = expected_acceptance(&expected);
        expected.cursor_floors.events = 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_ADMISSION);
        expected.cursor_floors.events = 0;
        expected.state_generation++;
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_EXPECTED_BINDING);
        expected = expected_binding(
            &manifest, chunks,
            ZCL_APP_CHECKPOINT_ADMISSION_RESTORE_SOURCE);
        acceptance = expected_acceptance(&expected);
        expected.grant_revision++;
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_EXPECTED_BINDING);
        expected = expected_binding(
            &manifest, chunks, ZCL_APP_CHECKPOINT_ADMISSION_INVALID);
        acceptance = expected_acceptance(&expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_ADMISSION);
        PASS();
    } _test_next:;
    return failures;
}

static int test_checkpoint_empty_roots_and_floors(void)
{
    int failures = 0;
    TEST("app checkpoint: empty roots are canonical and cursor floors are exact") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 manifest =
            valid_manifest(chunks);
        memset(manifest.events.root, 0, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_CURSOR);
        fill_root(manifest.events.root, 0x77);
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_CURSOR);
        manifest.events.sequence = 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);
        struct zcl_app_checkpoint_cursor_floors_v1 floors = {
            .events = 1,
        };
        ASSERT(zcl_app_checkpoint_cursors_meet_floors_v1(
            &manifest, &floors));
        floors.events = 2;
        ASSERT(!zcl_app_checkpoint_cursors_meet_floors_v1(
            &manifest, &floors));
        PASS();
    } _test_next:;
    return failures;
}

static int test_checkpoint_fork_quarantine(void)
{
    int failures = 0;
    TEST("app checkpoint: LLM forks quarantine effects and cannot switch live") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 parent = valid_manifest(chunks);
        struct zcl_app_checkpoint_expected_v1 parent_expected =
            expected_binding(&parent, chunks,
                             ZCL_APP_CHECKPOINT_ADMISSION_RESTORE_SOURCE);
        struct zcl_app_checkpoint_acceptance_v1 parent_acceptance =
            expected_acceptance(&parent_expected);
        struct zcl_app_checkpoint_expected_v1 live_scenario_expected =
            expected_binding(
                &parent, chunks,
                ZCL_APP_CHECKPOINT_ADMISSION_ISOLATED_SCENARIO);
        struct zcl_app_checkpoint_acceptance_v1 live_scenario_acceptance =
            expected_acceptance(&live_scenario_expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &parent, chunks, 2, &live_scenario_expected,
                      &live_scenario_acceptance, NULL, NULL, 0, NULL),
                  ZCL_APP_CHECKPOINT_ADMISSION);
        struct zcl_app_checkpoint_manifest_v1 manifest = parent;
        manifest.creation_cause = ZCL_APP_CHECKPOINT_CAUSE_LLM_FORK;
        manifest.state_origin = ZCL_APP_CHECKPOINT_ORIGIN_ISOLATED_FORK;
        manifest.outbox_mode = ZCL_APP_CHECKPOINT_OUTBOX_QUARANTINED;
        manifest.has_parent = 1;
        memcpy(manifest.parent_checkpoint_root,
               parent_expected.checkpoint_root, 32);
        manifest.state_generation++;
        fill_root(manifest.state_generation_root, 0x56);
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);
        struct zcl_app_checkpoint_expected_v1 expected = expected_binding(
            &manifest, chunks,
            ZCL_APP_CHECKPOINT_ADMISSION_PRODUCTION_SWITCH);
        bind_expected_parent(&expected, &parent_acceptance);
        struct zcl_app_checkpoint_acceptance_v1 acceptance =
            expected_acceptance(&expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      &parent, chunks, 2, &parent_acceptance),
                  ZCL_APP_CHECKPOINT_ADMISSION);
        expected = expected_binding(
            &manifest, chunks,
            ZCL_APP_CHECKPOINT_ADMISSION_ISOLATED_SCENARIO);
        bind_expected_parent(&expected, &parent_acceptance);
        acceptance = expected_acceptance(&expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      &parent, chunks, 2, &parent_acceptance),
                  ZCL_APP_CHECKPOINT_OK);
        struct zcl_app_checkpoint_acceptance_v1 fork_acceptance = acceptance;

        struct zcl_app_checkpoint_acceptance_v1 unordered_parent =
            parent_acceptance;
        unordered_parent.control_sequence = acceptance.control_sequence;
        struct zcl_app_checkpoint_expected_v1 unordered_expected =
            expected_binding(
                &manifest, chunks,
                ZCL_APP_CHECKPOINT_ADMISSION_ISOLATED_SCENARIO);
        (void)zcl_app_checkpoint_acceptance_digest_v1(
            &unordered_parent,
            unordered_expected.parent_acceptance_receipt_root);
        struct zcl_app_checkpoint_acceptance_v1 unordered_acceptance =
            expected_acceptance(&unordered_expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &unordered_expected,
                      &unordered_acceptance, &parent, chunks, 2,
                      &unordered_parent),
                  ZCL_APP_CHECKPOINT_ACCEPTANCE);

        memcpy(expected.scenario_grant_root, manifest.grant_root, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &manifest, chunks, 2, &expected, &acceptance,
                      &parent, chunks, 2, &parent_acceptance),
                  ZCL_APP_CHECKPOINT_ADMISSION);

        struct zcl_app_checkpoint_manifest_v1 relabeled = manifest;
        relabeled.creation_cause = ZCL_APP_CHECKPOINT_CAUSE_MANUAL;
        relabeled.state_origin = ZCL_APP_CHECKPOINT_ORIGIN_LIVE;
        relabeled.outbox_mode = ZCL_APP_CHECKPOINT_OUTBOX_CONTROLLED;
        memcpy(relabeled.parent_checkpoint_root,
               fork_acceptance.checkpoint_root, 32);
        struct zcl_app_checkpoint_expected_v1 relabeled_expected =
            expected_binding(
                &relabeled, chunks,
                ZCL_APP_CHECKPOINT_ADMISSION_PRODUCTION_SWITCH);
        bind_expected_parent(&relabeled_expected, &fork_acceptance);
        struct zcl_app_checkpoint_acceptance_v1 relabeled_acceptance =
            expected_acceptance(&relabeled_expected);
        ASSERT_EQ(zcl_app_checkpoint_validate_admission_v1(
                      &relabeled, chunks, 2, &relabeled_expected,
                      &relabeled_acceptance, &manifest, chunks, 2,
                      &fork_acceptance),
                  ZCL_APP_CHECKPOINT_ADMISSION);

        manifest.outbox_mode = ZCL_APP_CHECKPOINT_OUTBOX_CONTROLLED;
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_SIDE_EFFECT);
        PASS();
    } _test_next:;
    return failures;
}

static int test_checkpoint_lineage_taint(void)
{
    int failures = 0;
    TEST("app checkpoint: accepted parent lineage cannot shed scenario taint") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 live = valid_manifest(chunks);
        live.events.sequence = 5;
        fill_root(live.events.root, 0xd1);
        uint8_t live_root[32];
        ASSERT(zcl_app_checkpoint_digest_v1(&live, chunks, 2, live_root));

        struct zcl_app_checkpoint_manifest_v1 fork = live;
        fork.state_generation++;
        fill_root(fork.state_generation_root, 0xc1);
        fork.creation_cause = ZCL_APP_CHECKPOINT_CAUSE_LLM_FORK;
        fork.state_origin = ZCL_APP_CHECKPOINT_ORIGIN_ISOLATED_FORK;
        fork.outbox_mode = ZCL_APP_CHECKPOINT_OUTBOX_QUARANTINED;
        fork.has_parent = 1;
        memcpy(fork.parent_checkpoint_root, live_root, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &fork, chunks, 2, &live, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);

        struct zcl_app_checkpoint_manifest_v1 other_app = live;
        memcpy(other_app.app_id, "chat", 5);
        uint8_t other_app_root[32];
        ASSERT(zcl_app_checkpoint_digest_v1(
            &other_app, chunks, 2, other_app_root));
        memcpy(fork.parent_checkpoint_root, other_app_root, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &fork, chunks, 2, &other_app, chunks, 2),
                  ZCL_APP_CHECKPOINT_CAUSALITY);
        memcpy(fork.parent_checkpoint_root, live_root, 32);

        fork.events.root[0] ^= 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &fork, chunks, 2, &live, chunks, 2),
                  ZCL_APP_CHECKPOINT_CURSOR);
        fork.events.root[0] ^= 1;

        uint8_t fork_root[32];
        ASSERT(zcl_app_checkpoint_digest_v1(&fork, chunks, 2, fork_root));
        struct zcl_app_checkpoint_manifest_v1 scheduled = fork;
        scheduled.creation_cause = ZCL_APP_CHECKPOINT_CAUSE_SCHEDULED;
        memcpy(scheduled.parent_checkpoint_root, fork_root, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &scheduled, chunks, 2, &fork, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);
        scheduled.state_generation++;
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &scheduled, chunks, 2, &fork, chunks, 2),
                  ZCL_APP_CHECKPOINT_GENERATION);

        struct zcl_app_checkpoint_manifest_v1 migration = live;
        migration.creation_cause = ZCL_APP_CHECKPOINT_CAUSE_MIGRATION;
        migration.has_parent = 1;
        memcpy(migration.parent_checkpoint_root, live_root, 32);
        migration.state_generation++;
        fill_root(migration.state_generation_root, 0xc3);
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &migration, chunks, 2, &live, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);
        migration.state_generation = live.state_generation;
        memcpy(migration.state_generation_root,
               live.state_generation_root, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &migration, chunks, 2, &live, chunks, 2),
                  ZCL_APP_CHECKPOINT_GENERATION);

        struct zcl_app_checkpoint_manifest_v1 relabeled = fork;
        relabeled.creation_cause = ZCL_APP_CHECKPOINT_CAUSE_MANUAL;
        relabeled.state_origin = ZCL_APP_CHECKPOINT_ORIGIN_LIVE;
        relabeled.outbox_mode = ZCL_APP_CHECKPOINT_OUTBOX_CONTROLLED;
        memcpy(relabeled.parent_checkpoint_root, fork_root, 32);
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &relabeled, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &relabeled, chunks, 2, &fork, chunks, 2),
                  ZCL_APP_CHECKPOINT_ADMISSION);
        relabeled.parent_checkpoint_root[0] ^= 1;
        ASSERT_EQ(zcl_app_checkpoint_validate_lineage_v1(
                      &relabeled, chunks, 2, &fork, chunks, 2),
                  ZCL_APP_CHECKPOINT_CAUSALITY);
        PASS();
    } _test_next:;
    return failures;
}

static struct zcl_app_warm_cache_v1 valid_warm_cache(void)
{
    struct zcl_app_warm_cache_v1 cache = {0};
    cache.present = 1;
    cache.format_version = ZCL_APP_WARM_CACHE_FORMAT_V1;
    cache.architecture = ZCL_APP_WARM_ARCH_X86_64;
    cache.endianness = ZCL_APP_WARM_ENDIAN_LITTLE;
    cache.data_model_bits = 64;
    cache.page_size = 4096;
    cache.alignment = 64;
    cache.encoding_flags = ZCL_APP_WARM_REQUIRED_ENCODING_V1;
    cache.region_count = 2;
    cache.cpu_feature_floor[0] = 0x5;
    cache.byte_length = 8192;
    fill_root(cache.root, 0x91);
    return cache;
}

static int test_warm_cache_is_detachable(void)
{
    int failures = 0;
    TEST("app checkpoint: warm cache is compatible-or-discard, never authority") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 manifest =
            valid_manifest(chunks);
        uint8_t portable_a[32];
        uint8_t portable_b[32];
        ASSERT(zcl_app_checkpoint_digest_v1(
            &manifest, chunks, 2, portable_a));
        struct zcl_app_warm_cache_v1 cache = valid_warm_cache();
        ASSERT_EQ(zcl_app_checkpoint_validate_structure_v1(
                      &manifest, chunks, 2),
                  ZCL_APP_CHECKPOINT_OK);
        ASSERT(zcl_app_checkpoint_digest_v1(
            &manifest, chunks, 2, portable_b));
        ASSERT(memcmp(portable_a, portable_b, 32) == 0);
        uint8_t attachment[32];
        ASSERT(zcl_app_warm_cache_attachment_digest_v1(
            portable_a, &cache, attachment));
        ASSERT(!root_is_zero(attachment));

        struct zcl_app_warm_cache_host_v1 host = {
            .struct_size = sizeof(host),
            .format_version = ZCL_APP_WARM_CACHE_FORMAT_V1,
            .architecture = ZCL_APP_WARM_ARCH_X86_64,
            .endianness = ZCL_APP_WARM_ENDIAN_LITTLE,
            .data_model_bits = 64,
            .page_size = 4096,
            .cpu_features = { 0x7, 0 },
        };
        ASSERT(zcl_app_warm_cache_compatible_v1(
            &cache, &host));
        ASSERT(zcl_app_warm_cache_admitted_v1(
            &cache, portable_a, attachment, &host));
        uint8_t wrong_attachment[32];
        fill_root(wrong_attachment, 0xf1);
        ASSERT(!zcl_app_warm_cache_admitted_v1(
            &cache, portable_a, wrong_attachment, &host));
        host.cpu_features[0] = 0x1;
        ASSERT(!zcl_app_warm_cache_compatible_v1(
            &cache, &host));
        host.cpu_features[0] = 0x7;
        host.architecture = ZCL_APP_WARM_ARCH_AARCH64;
        ASSERT(!zcl_app_warm_cache_compatible_v1(
            &cache, &host));
        cache.encoding_flags &= ~ZCL_APP_WARM_ZERO_PADDING;
        ASSERT(!zcl_app_warm_cache_attachment_digest_v1(
            portable_a, &cache, wrong_attachment));
        ASSERT(zcl_app_checkpoint_digest_v1(
            &manifest, chunks, 2, portable_b));
        ASSERT(memcmp(portable_a, portable_b, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_checkpoint_acceptance_receipt(void)
{
    int failures = 0;
    TEST("app checkpoint: journal acceptance is a separate non-circular receipt") {
        struct zcl_app_state_chunk_v1 chunks[2];
        make_chunks(chunks);
        struct zcl_app_checkpoint_manifest_v1 manifest =
            valid_manifest(chunks);
        uint8_t checkpoint_root[32];
        ASSERT(zcl_app_checkpoint_digest_v1(
            &manifest, chunks, 2, checkpoint_root));
        struct zcl_app_checkpoint_acceptance_v1 receipt = {
            .struct_size = sizeof(receipt),
            .schema_version = ZCL_APP_CHECKPOINT_ACCEPTANCE_V1,
            .control_sequence = 42,
            .accepting_service_id = 5,
        };
        memcpy(receipt.checkpoint_root, checkpoint_root, 32);
        fill_root(receipt.control_event_id, 0xa1);
        fill_root(receipt.control_segment_root, 0xa2);
        ASSERT_EQ(zcl_app_checkpoint_acceptance_validate_v1(
                      &receipt, checkpoint_root),
                  ZCL_APP_CHECKPOINT_OK);
        uint8_t receipt_root[32];
        ASSERT(zcl_app_checkpoint_acceptance_digest_v1(
            &receipt, receipt_root));
        ASSERT(!root_is_zero(receipt_root));
        uint8_t wrong_root[32];
        fill_root(wrong_root, 0xee);
        ASSERT_EQ(zcl_app_checkpoint_acceptance_validate_v1(
                      &receipt, wrong_root),
                  ZCL_APP_CHECKPOINT_EXPECTED_BINDING);
        receipt.control_sequence = 0;
        ASSERT(!zcl_app_checkpoint_acceptance_digest_v1(
            &receipt, receipt_root));
        ASSERT(root_is_zero(receipt_root));
        PASS();
    } _test_next:;
    return failures;
}

int test_app_checkpoint_manifest(void)
{
    int failures = 0;
    failures += test_checkpoint_valid_and_canonical();
    failures += test_checkpoint_chunk_layout();
    failures += test_state_chunk_domain();
    failures += test_checkpoint_exact_binding();
    failures += test_checkpoint_empty_roots_and_floors();
    failures += test_checkpoint_fork_quarantine();
    failures += test_checkpoint_lineage_taint();
    failures += test_warm_cache_is_detachable();
    failures += test_checkpoint_acceptance_receipt();
    return failures;
}
