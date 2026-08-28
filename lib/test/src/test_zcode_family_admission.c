/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Family admission codec, projection and reversal-gate fixtures. */
#include "test/test_core.h"

#include "base/hex.h"
#include "vcs/zcode_family_admission.h"

#include <stdio.h>
#include <string.h>

static const char admission_root_kat[] =
    "6acb9bf015d3aec35bd5db76e9a14e7713ecde291a29456593b0d2eecb1c196f";
static const char projection_root_kat[] =
    "69cbb7b4cf90120d01d09074bc72ce61fdcb06f8409a46181fa9c7c5683fde4f";

static void family_fill(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static bool family_policy_root(uint8_t out[32])
{
    struct vcs_zcode_family_policy_v1 policy;
    vcs_zcode_family_policy_v1_default(&policy);
    return vcs_zcode_family_policy_v1_root(&policy, out) ==
           VCS_ZCODE_COMMONS_OK;
}

static bool family_make_admission(
    struct vcs_zcode_commons_admission_v1 *admission,
    uint64_t sequence, enum vcs_zcode_commons_admission_state_v1 state,
    enum vcs_zcode_moderation_tier_v1 tier,
    const uint8_t policy_root[32], const uint8_t moderation_root[32],
    const uint8_t predecessor[32], uint8_t seed_byte)
{
    memset(admission, 0, sizeof(*admission));
    admission->schema_version = 1;
    admission->flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    admission->state = (uint16_t)state;
    admission->tier = (uint16_t)tier;
    admission->coverage_complete = 1;
    admission->closure_complete = 1;
    admission->sequence = sequence;
    admission->decided_height = 100u + sequence;
    admission->decided_mtp = 1000 + (int64_t)sequence;
    admission->expires_height = 1000;
    admission->expires_mtp = 10000;
    family_fill(admission->content_root, 0x21);
    family_fill(admission->dependency_closure_root, 0x22);
    memcpy(admission->family_policy_root, policy_root, 32);
    memcpy(admission->moderation_set_root, moderation_root, 32);
    family_fill(admission->panel_root, (uint8_t)(0x30u + sequence));
    family_fill(admission->evidence_root, (uint8_t)(0x40u + seed_byte));
    if (predecessor)
        memcpy(admission->predecessor_admission_root, predecessor, 32);
    uint8_t seed[32];
    family_fill(seed, seed_byte);
    return vcs_zcode_commons_admission_v1_sign(admission, seed) ==
           VCS_ZCODE_FAMILY_ADMISSION_OK;
}

static bool family_source(
    struct vcs_zcode_family_admission_source_v1 *source,
    const struct vcs_zcode_commons_admission_v1 *admission)
{
    memset(source, 0, sizeof(*source));
    source->admission = *admission;
    return vcs_zcode_commons_admission_v1_root(
               admission, source->object_root) ==
           VCS_ZCODE_FAMILY_ADMISSION_OK;
}

static struct vcs_zcode_family_projection_config_v1 family_config(
    const uint8_t policy_root[32], const uint8_t moderation_root[32])
{
    struct vcs_zcode_family_projection_config_v1 config;
    memset(&config, 0, sizeof(config));
    memcpy(config.family_policy_root, policy_root, 32);
    memcpy(config.moderation_set_root, moderation_root, 32);
    family_fill(config.chain_tip_root, 0x61);
    config.cutoff_height = 200;
    config.cutoff_mtp = 2000;
    config.required_tier = VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS;
    config.chain_current = true;
    return config;
}

static int test_admission_codec(void)
{
    int failures = 0;
    TEST("commons_admission.v1 is canonical, signed and root-addressed") {
        uint8_t policy[32], moderation[32];
        ASSERT(family_policy_root(policy));
        family_fill(moderation, 0x51);
        struct vcs_zcode_commons_admission_v1 admission;
        ASSERT(family_make_admission(
            &admission, 1, VCS_ZCODE_ADMISSION_BOOTSTRAP_PASS,
            VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS,
            policy, moderation, NULL, 0x71));
        uint8_t wire[VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_commons_admission_v1_encode(
                      &admission, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        ASSERT_EQ(wire_len, VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES);
        struct vcs_zcode_commons_admission_v1 decoded;
        ASSERT_EQ(vcs_zcode_commons_admission_v1_decode(
                      &decoded, wire, wire_len),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        uint8_t root[32];
        ASSERT_EQ(vcs_zcode_commons_admission_v1_root(&decoded, root),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        char hex[65]; zcl_hex_encode(root, 32, hex);
        printf("commons_admission.v1=%s\n", hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(admission_root_kat, expected, 32));
        ASSERT(memcmp(root, expected, 32) == 0);
        wire[60] ^= 1u;
        ASSERT_EQ(vcs_zcode_commons_admission_v1_decode(
                      &decoded, wire, wire_len),
                  VCS_ZCODE_FAMILY_ADMISSION_SIGNATURE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_projection_reversals(void)
{
    int failures = 0;
    TEST("Family projection is order-invariant and reversals fail closed") {
        uint8_t policy[32], moderation[32];
        ASSERT(family_policy_root(policy));
        family_fill(moderation, 0x51);
        struct vcs_zcode_commons_admission_v1 pass, reverse;
        ASSERT(family_make_admission(
            &pass, 1, VCS_ZCODE_ADMISSION_BOOTSTRAP_PASS,
            VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS,
            policy, moderation, NULL, 0x71));
        uint8_t pass_root[32];
        ASSERT_EQ(vcs_zcode_commons_admission_v1_root(&pass, pass_root),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        ASSERT(family_make_admission(
            &reverse, 2, VCS_ZCODE_ADMISSION_RESTRICTED,
            VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS,
            policy, moderation, pass_root, 0x72));
        struct vcs_zcode_family_admission_source_v1 source[2];
        ASSERT(family_source(&source[0], &pass));
        ASSERT(family_source(&source[1], &reverse));
        struct vcs_zcode_family_projection_config_v1 config =
            family_config(policy, moderation);
        struct vcs_zcode_family_admission_projection *visible = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, source, 1, &visible),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        const struct vcs_zcode_family_admission_projection_entry_v1 *entry =
            vcs_zcode_family_admission_projection_at_v1(visible, 0);
        ASSERT(entry && entry->family_public && entry->chain_complete);
        uint8_t visible_root[32];
        vcs_zcode_family_admission_projection_root_v1(
            visible, visible_root);
        char hex[65]; zcl_hex_encode(visible_root, 32, hex);
        printf("family_admission_projection.v1=%s\n", hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(projection_root_kat, expected, 32));
        ASSERT(memcmp(visible_root, expected, 32) == 0);

        struct vcs_zcode_family_admission_projection *reversed_a = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, source, 2, &reversed_a),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        struct vcs_zcode_family_admission_source_v1 unordered[2] = {
            source[1], source[0]
        };
        struct vcs_zcode_family_admission_projection *reversed_b = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, unordered, 2, &reversed_b),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        uint8_t root_a[32], root_b[32];
        vcs_zcode_family_admission_projection_root_v1(reversed_a, root_a);
        vcs_zcode_family_admission_projection_root_v1(reversed_b, root_b);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        entry = vcs_zcode_family_admission_projection_find_v1(
            reversed_a, pass.content_root, pass.dependency_closure_root);
        ASSERT(entry && !entry->family_public && entry->current &&
               entry->state == VCS_ZCODE_ADMISSION_RESTRICTED);

        struct vcs_zcode_family_admission_projection *incomplete = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, &source[1], 1, &incomplete),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        entry = vcs_zcode_family_admission_projection_at_v1(incomplete, 0);
        ASSERT(entry && !entry->chain_complete && !entry->family_public);
        config.required_tier = VCS_ZCODE_MODERATION_TIER_PEERED_PASS;
        struct vcs_zcode_family_admission_projection *ratcheted = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, source, 1, &ratcheted),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        entry = vcs_zcode_family_admission_projection_at_v1(ratcheted, 0);
        ASSERT(entry && !entry->current && !entry->family_public);
        config.required_tier = VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS;
        config.chain_current = false;
        struct vcs_zcode_family_admission_projection *stale = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, source, 1, &stale),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        entry = vcs_zcode_family_admission_projection_at_v1(stale, 0);
        ASSERT(entry && !entry->current && !entry->family_public);

        config.chain_current = true;
        struct vcs_zcode_commons_admission_v1 fork;
        ASSERT(family_make_admission(
            &fork, 2, VCS_ZCODE_ADMISSION_RESTRICTED,
            VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS,
            policy, moderation, pass_root, 0x73));
        struct vcs_zcode_family_admission_source_v1 branched[3];
        memset(branched, 0, sizeof(branched));
        branched[0] = source[0];
        branched[1] = source[1];
        ASSERT(family_source(&branched[2], &fork));
        struct vcs_zcode_family_admission_projection *conflicted = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, branched, 3, &conflicted),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        entry = vcs_zcode_family_admission_projection_at_v1(conflicted, 0);
        ASSERT(entry && entry->state == VCS_ZCODE_ADMISSION_CONFLICTED &&
               !entry->chain_complete && !entry->family_public);
        vcs_zcode_family_admission_projection_free_v1(conflicted);
        vcs_zcode_family_admission_projection_free_v1(stale);
        vcs_zcode_family_admission_projection_free_v1(ratcheted);
        vcs_zcode_family_admission_projection_free_v1(incomplete);
        vcs_zcode_family_admission_projection_free_v1(reversed_b);
        vcs_zcode_family_admission_projection_free_v1(reversed_a);
        vcs_zcode_family_admission_projection_free_v1(visible);
        PASS();
    } _test_next:;
    return failures;
}

static bool family_local_decide(
    void *ctx, enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject)
{
    (void)action;
    (void)subject;
    return ctx && *(const bool *)ctx;
}

static void family_public_request(
    struct vcs_zcode_family_access_request_v1 *request)
{
    memset(request, 0, sizeof(*request));
    request->action = VCS_ZCODE_FAMILY_ACTION_PREVIEW;
    request->intent = VCS_ZCODE_FAMILY_INTENT_FAMILY_PUBLIC;
    family_fill(request->content_root, 0x21);
    family_fill(request->dependency_closure_root, 0x22);
    memcpy(request->subject.package_root, request->content_root, 32);
}

static int test_composite_access_recheck(void)
{
    int failures = 0;
    TEST("queued Family actions bind a generation and reversal wins the race") {
        uint8_t policy[32], moderation[32];
        ASSERT(family_policy_root(policy));
        family_fill(moderation, 0x51);
        struct vcs_zcode_commons_admission_v1 pass, reverse;
        ASSERT(family_make_admission(
            &pass, 1, VCS_ZCODE_ADMISSION_BOOTSTRAP_PASS,
            VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS,
            policy, moderation, NULL, 0x71));
        uint8_t pass_root[32];
        ASSERT_EQ(vcs_zcode_commons_admission_v1_root(&pass, pass_root),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        ASSERT(family_make_admission(
            &reverse, 2, VCS_ZCODE_ADMISSION_RESTRICTED,
            VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS,
            policy, moderation, pass_root, 0x72));
        struct vcs_zcode_family_admission_source_v1 source[2];
        ASSERT(family_source(&source[0], &pass));
        ASSERT(family_source(&source[1], &reverse));
        struct vcs_zcode_family_projection_config_v1 config =
            family_config(policy, moderation);
        struct vcs_zcode_family_admission_projection *visible = NULL;
        struct vcs_zcode_family_admission_projection *reversed = NULL;
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, source, 1, &visible),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        ASSERT_EQ(vcs_zcode_family_admission_projection_build_v1(
                      &config, source, 2, &reversed),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        struct vcs_zcode_family_access_service *service =
            vcs_zcode_family_access_service_create();
        ASSERT(service != NULL && !vcs_zcode_family_access_service_active(
                                      service));
        bool local_allow = true, local_block = false;
        struct vcs_zcode_family_access_request_v1 request;
        family_public_request(&request);
        struct vcs_zcode_family_access_decision_v1 decision =
            vcs_zcode_family_access_decide_v1(
                service, family_local_decide, &local_allow, &request);
        ASSERT(decision.allow &&
               decision.reason == VCS_ZCODE_FAMILY_ACCESS_INACTIVE);
        ASSERT(!vcs_zcode_family_access_decide_v1(
                    service, family_local_decide, &local_block, &request).allow);
        ASSERT_EQ(vcs_zcode_family_access_service_publish(service, visible),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        ASSERT_EQ(vcs_zcode_family_access_service_set_active(service, true),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        decision = vcs_zcode_family_access_decide_v1(
            service, family_local_decide, &local_allow, &request);
        ASSERT(decision.allow && decision.enforcement_active &&
               decision.reason == VCS_ZCODE_FAMILY_ACCESS_FAMILY_PUBLIC);
        struct vcs_zcode_family_access_binding_v1 binding;
        ASSERT(vcs_zcode_family_access_bind_v1(
            &request, &decision, &binding));
        ASSERT_EQ(vcs_zcode_family_access_service_publish(service, reversed),
                  VCS_ZCODE_FAMILY_ADMISSION_OK);
        decision = vcs_zcode_family_access_recheck_v1(
            service, family_local_decide, &local_allow, &request, &binding);
        ASSERT(!decision.allow && decision.generation_changed &&
               decision.reason == VCS_ZCODE_FAMILY_ACCESS_NOT_ADMITTED);

        request.action = VCS_ZCODE_FAMILY_ACTION_SHOW;
        request.intent = VCS_ZCODE_FAMILY_INTENT_EXACT_ROOT_DIAGNOSTIC;
        request.operator_authorized = true;
        request.redacted = true;
        ASSERT(vcs_zcode_family_access_decide_v1(
                   service, family_local_decide, &local_allow, &request).allow);
        request.action = VCS_ZCODE_FAMILY_ACTION_PREVIEW;
        ASSERT(!vcs_zcode_family_access_decide_v1(
                    service, family_local_decide, &local_allow, &request).allow);

        family_public_request(&request);
        request.action = VCS_ZCODE_FAMILY_ACTION_FETCH;
        request.intent = VCS_ZCODE_FAMILY_INTENT_MODERATION_INTAKE;
        family_fill(request.provider_root, 0x81);
        request.expected_bytes = 1024;
        request.byte_budget = 2048;
        request.current_height = 200;
        request.current_mtp = 2000;
        request.expires_height = 201;
        request.expires_mtp = 2001;
        ASSERT(vcs_zcode_family_access_decide_v1(
                   service, family_local_decide, &local_allow, &request).allow);
        request.byte_budget = VCS_ZCODE_FAMILY_INTAKE_MAX_BYTES + 1u;
        ASSERT(!vcs_zcode_family_access_decide_v1(
                    service, family_local_decide, &local_allow, &request).allow);

        memset(&request, 0, sizeof(request));
        request.action = VCS_ZCODE_FAMILY_ACTION_PROTOCOL_FRAME;
        request.intent = VCS_ZCODE_FAMILY_INTENT_PROTOCOL_CONTROL;
        request.control_kind = VCS_ZCODE_FAMILY_CONTROL_DHT_QUERY;
        request.control_bytes = 64;
        ASSERT(vcs_zcode_family_access_decide_v1(
                   service, family_local_decide, &local_allow, &request).allow);
        request.control_bytes = VCS_ZCODE_FAMILY_CONTROL_MAX_BYTES + 1u;
        ASSERT(!vcs_zcode_family_access_decide_v1(
                    service, family_local_decide, &local_allow, &request).allow);
        vcs_zcode_family_access_service_free(service);
        vcs_zcode_family_admission_projection_free_v1(reversed);
        vcs_zcode_family_admission_projection_free_v1(visible);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_family_admission(void)
{
    int failures = test_admission_codec() + test_projection_reversals() +
                   test_composite_access_recheck();
    printf("=== zcode_family_admission: %d failures ===\n", failures);
    return failures;
}
