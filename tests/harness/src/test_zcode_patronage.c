/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove ZC23 patronage offer/funding/settlement wire codecs and that
 * the simulated settlement lifecycle fails closed on every live-money path. */
#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_contributor_binding.h"
#include "vcs/zcode_patronage.h"
#include "vcs/zcode_patronage_funding.h"
#include "vcs/zcode_patronage_projection.h"
#include "vcs/zcode_patronage_settlement.h"

#include <string.h>

#define PATRONAGE_GIFT_AMOUNT UINT64_C(500000000)

static void patronage_fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static void patronage_gift_intent(
    struct vcs_zcode_patronage_intent_v1 *intent, const uint8_t network[32],
    const uint8_t patron_binding_root[32], const uint8_t patron_pubkey[32],
    const uint8_t recipient_binding_root[32], uint8_t trust_mode)
{
    memset(intent, 0, sizeof(*intent));
    intent->schema_version = VCS_ZCODE_PATRONAGE_INTENT_VERSION;
    intent->mode = VCS_ZCODE_PATRONAGE_DIRECT_GIFT;
    intent->target_kind = VCS_ZCODE_PATRONAGE_TARGET_CONTRIBUTOR;
    intent->settlement_trust_mode = trust_mode;
    intent->flags = VCS_ZCODE_PATRONAGE_NO_AUTHORITY |
                    VCS_ZCODE_PATRONAGE_SIMULATION_ONLY;
    memcpy(intent->network_genesis_root, network, 32);
    patronage_fill(intent->zc23_token_or_simulation_root, 32);
    memcpy(intent->patron_contributor_binding_root, patron_binding_root, 32);
    memcpy(intent->patron_zid_pubkey, patron_pubkey, 32);
    memcpy(intent->target_root, recipient_binding_root, 32);
    memcpy(intent->intended_recipient_binding_root,
           recipient_binding_root, 32);
    intent->amount_atoms = PATRONAGE_GIFT_AMOUNT;
    intent->created_unix = 1000;
    intent->expires_unix = 2000;
    intent->sequence = 1;
    intent->maximum_zcl_fee_zat = 10000;
}

static void patronage_funding_fixture(
    struct vcs_zcode_patronage_funding_v1 *funding, const uint8_t network[32],
    const uint8_t intent_root[32], const uint8_t patron_binding_root[32],
    const uint8_t patron_pubkey[32])
{
    memset(funding, 0, sizeof(*funding));
    funding->schema_version = VCS_ZCODE_PATRONAGE_FUNDING_VERSION;
    funding->funding_kind = VCS_ZCODE_PATRONAGE_FUNDING_FULLY_SIMULATED;
    funding->flags = VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS |
                     VCS_ZCODE_PATRONAGE_FUNDING_NO_TRANSACTION_BYTES;
    memcpy(funding->network_genesis_root, network, 32);
    memcpy(funding->patronage_intent_root, intent_root, 32);
    memcpy(funding->funder_contributor_binding_root,
           patron_binding_root, 32);
    memcpy(funding->funder_zid_pubkey, patron_pubkey, 32);
    funding->amount_atoms = PATRONAGE_GIFT_AMOUNT;
    funding->created_unix = 1500;
    funding->sequence = 1;
    (void)vcs_zcode_patronage_simulation_plan_root(
        intent_root, PATRONAGE_GIFT_AMOUNT, funding->simulation_plan_root);
}

static int patronage_intent_gift_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage intent: direct-gift wire is exact and non-authoritative") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 42, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        uint8_t network[32], patron_binding[32], recipient_binding[32];
        patronage_fill(network, 0xc1);
        patronage_fill(patron_binding, 33);
        patronage_fill(recipient_binding, 36);

        struct vcs_zcode_patronage_intent_v1 intent, parsed, zero;
        memset(&zero, 0, sizeof(zero));
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        ASSERT_EQ(vcs_zcode_patronage_intent_seal(&intent, secret, pubkey),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_verify(&intent, 1000),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_verify(&intent, 1999),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_verify(&intent, 999),
                  VCS_ZCODE_PATRONAGE_TIME);
        ASSERT_EQ(vcs_zcode_patronage_intent_verify(&intent, 2000),
                  VCS_ZCODE_PATRONAGE_TIME);

        uint8_t wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_patronage_intent_serialize(&intent, wire),
                  VCS_ZCODE_PATRONAGE_OK);
        static const uint8_t prefix_kat[16] = {
            'Z','C','P','A','T','R','\r','\n',
            0x01, 0x00, 0x03, 0x04, 0x01, 0x05, 0x00, 0x00,
        };
        ASSERT(memcmp(wire, prefix_kat, sizeof(prefix_kat)) == 0);
        ASSERT_EQ(vcs_zcode_patronage_intent_parse(wire, sizeof(wire),
                                                   &parsed),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_serialize(&parsed, second),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT(memcmp(wire, second, sizeof(wire)) == 0);
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(vcs_zcode_patronage_intent_root(&intent, root_a),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_root(&parsed, root_b),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);

        for (size_t cut = 0; cut < sizeof(wire); cut++) {
            ASSERT_EQ(vcs_zcode_patronage_intent_parse(wire, cut, &parsed),
                      VCS_ZCODE_PATRONAGE_WIRE_SIZE);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        uint8_t malformed[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES + 1];
        memcpy(malformed, wire, sizeof(wire));
        malformed[sizeof(wire)] = 0;
        ASSERT_EQ(vcs_zcode_patronage_intent_parse(
                      malformed, sizeof(malformed), &parsed),
                  VCS_ZCODE_PATRONAGE_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        malformed[0] ^= 1;
        ASSERT_EQ(vcs_zcode_patronage_intent_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_PATRONAGE_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire));
        malformed[14] = 1; /* reserved u16 must stay zero */
        ASSERT_EQ(vcs_zcode_patronage_intent_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_PATRONAGE_SHAPE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire));
        malformed[sizeof(wire) - 1] ^= 1;
        ASSERT_EQ(vcs_zcode_patronage_intent_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_verify(&parsed, 1500),
                  VCS_ZCODE_PATRONAGE_SIGNATURE);

        /* Direct-gift shape: no refund schedule, no proof roots, no task
         * target — any of them present is rejected. */
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        intent.refund_height = 3000;
        ASSERT_EQ(vcs_zcode_patronage_intent_validate(&intent),
                  VCS_ZCODE_PATRONAGE_SHAPE);
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        patronage_fill(intent.task_root, 34);
        ASSERT_EQ(vcs_zcode_patronage_intent_validate(&intent),
                  VCS_ZCODE_PATRONAGE_SHAPE);
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        intent.target_kind = VCS_ZCODE_PATRONAGE_TARGET_TASK;
        ASSERT_EQ(vcs_zcode_patronage_intent_validate(&intent),
                  VCS_ZCODE_PATRONAGE_SHAPE);
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        intent.mode = 0;
        ASSERT_EQ(vcs_zcode_patronage_intent_validate(&intent),
                  VCS_ZCODE_PATRONAGE_ENUM);
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        intent.settlement_trust_mode = 0;
        ASSERT_EQ(vcs_zcode_patronage_intent_validate(&intent),
                  VCS_ZCODE_PATRONAGE_ENUM);
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        intent.amount_atoms = 0;
        ASSERT_EQ(vcs_zcode_patronage_intent_validate(&intent),
                  VCS_ZCODE_PATRONAGE_AMOUNT);
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        intent.flags &= (uint8_t)~VCS_ZCODE_PATRONAGE_SIMULATION_ONLY;
        ASSERT_EQ(vcs_zcode_patronage_intent_validate(&intent),
                  VCS_ZCODE_PATRONAGE_FLAGS);

        /* CAS verification fails closed before any authority is granted. */
        patronage_gift_intent(&intent, network, patron_binding, pubkey,
                              recipient_binding,
                              VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER);
        ASSERT_EQ(vcs_zcode_patronage_intent_seal(&intent, secret, pubkey),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(&intent, NULL),
                  VCS_ZCODE_PATRONAGE_TIME);
        struct vcs_zcode_patronage_validation_context context = {
            .workspace = NULL,
            .expected_network_genesis_root = network,
            .now_unix = 1500,
        };
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(&intent, &context),
                  VCS_ZCODE_PATRONAGE_CONTEXT);
        uint8_t other_network[32];
        patronage_fill(other_network, 0xc2);
        context.workspace = "./test-tmp";
        context.expected_network_genesis_root = other_network;
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(&intent, &context),
                  VCS_ZCODE_PATRONAGE_NETWORK);
        PASS();
    } _test_next:;
    return failures;
}

static int patronage_funding_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage funding: simulated receipt wire rejects live funds") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 51, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        uint8_t network[32], patron_binding[32], intent_root[32];
        patronage_fill(network, 0xc1);
        patronage_fill(patron_binding, 33);
        patronage_fill(intent_root, 41);

        /* Simulation plan root is pure deterministic arithmetic. */
        uint8_t plan_a[32], plan_b[32];
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, PATRONAGE_GIFT_AMOUNT, NULL),
                  VCS_ZCODE_PATRONAGE_FUNDING_NULL);
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      NULL, PATRONAGE_GIFT_AMOUNT, plan_a),
                  VCS_ZCODE_PATRONAGE_FUNDING_NULL);
        uint8_t zero_root[32] = {0};
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      zero_root, PATRONAGE_GIFT_AMOUNT, plan_a),
                  VCS_ZCODE_PATRONAGE_FUNDING_ROOT);
        ASSERT(memcmp(plan_a, zero_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, 0, plan_a),
                  VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT);
        ASSERT(memcmp(plan_a, zero_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, PATRONAGE_GIFT_AMOUNT, plan_a),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, PATRONAGE_GIFT_AMOUNT, plan_b),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT(memcmp(plan_a, plan_b, 32) == 0);
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, PATRONAGE_GIFT_AMOUNT + 1, plan_b),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT(memcmp(plan_a, plan_b, 32) != 0);

        struct vcs_zcode_patronage_funding_v1 funding, parsed, zero;
        memset(&zero, 0, sizeof(zero));
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(&funding, secret, pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_verify(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);

        uint8_t wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_patronage_funding_serialize(&funding, wire),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        static const uint8_t prefix_kat[16] = {
            'Z','C','P','F','U','N','\r','\n',
            0x01, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
        };
        ASSERT(memcmp(wire, prefix_kat, sizeof(prefix_kat)) == 0);
        ASSERT_EQ(vcs_zcode_patronage_funding_parse(wire, sizeof(wire),
                                                    &parsed),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_serialize(&parsed, second),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT(memcmp(wire, second, sizeof(wire)) == 0);
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(vcs_zcode_patronage_funding_root(&funding, root_a),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_root(&parsed, root_b),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);

        for (size_t cut = 0; cut < sizeof(wire); cut++) {
            ASSERT_EQ(vcs_zcode_patronage_funding_parse(wire, cut, &parsed),
                      VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        uint8_t malformed[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES + 1];
        memcpy(malformed, wire, sizeof(wire));
        malformed[sizeof(wire)] = 0;
        ASSERT_EQ(vcs_zcode_patronage_funding_parse(
                      malformed, sizeof(malformed), &parsed),
                  VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        malformed[0] ^= 1;
        ASSERT_EQ(vcs_zcode_patronage_funding_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_PATRONAGE_FUNDING_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire));
        malformed[12] = 1; /* reserved u32 must stay zero */
        ASSERT_EQ(vcs_zcode_patronage_funding_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_PATRONAGE_FUNDING_SHAPE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire));
        malformed[sizeof(wire) - 1] ^= 1;
        ASSERT_EQ(vcs_zcode_patronage_funding_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_verify(&parsed),
                  VCS_ZCODE_PATRONAGE_FUNDING_SIGNATURE);

        /* The simulation-only shape is mandatory: clearing the no-live-funds
         * flag, faking the plan root, or wrong kind all fail closed. */
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        funding.flags &= (uint8_t)~VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS;
        ASSERT_EQ(vcs_zcode_patronage_funding_validate(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_SHAPE);
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        funding.flags &=
            (uint8_t)~VCS_ZCODE_PATRONAGE_FUNDING_NO_TRANSACTION_BYTES;
        ASSERT_EQ(vcs_zcode_patronage_funding_validate(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_SHAPE);
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        funding.funding_kind = 2;
        ASSERT_EQ(vcs_zcode_patronage_funding_validate(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_SHAPE);
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        patronage_fill(funding.simulation_plan_root, 99);
        ASSERT_EQ(vcs_zcode_patronage_funding_validate(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_ROOT);
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        funding.amount_atoms = 0;
        ASSERT_EQ(vcs_zcode_patronage_funding_validate(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT);
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        funding.sequence = 0;
        ASSERT_EQ(vcs_zcode_patronage_funding_validate(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_TIME);

        /* CAS verification requires the intent object and a live window. */
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_patronage_funding", "empty");
        ASSERT(vcs_object_store_init(workspace));
        patronage_funding_fixture(&funding, network, intent_root,
                                  patron_binding, pubkey);
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(&funding, secret, pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        struct vcs_zcode_patronage_validation_context context = {
            .workspace = workspace,
            .expected_network_genesis_root = network,
            .now_unix = 1600,
        };
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(&funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_INTENT);
        context.now_unix = 1400; /* funding.created_unix (1500) is future */
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(&funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_TIME);
        context.workspace = NULL;
        context.now_unix = 1600;
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(&funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_CONTEXT);
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(&funding, NULL),
                  VCS_ZCODE_PATRONAGE_FUNDING_CONTEXT);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

struct patronage_lifecycle {
    char workspace[256];
    uint8_t network[32];
    uint8_t patron_pubkey[32];
    uint8_t patron_secret[32];
    uint8_t patron_binding_root[32];
    uint8_t recipient_binding_root[32];
    struct vcs_zcode_patronage_intent_v1 intent;
    uint8_t intent_root[32];
    struct vcs_zcode_patronage_funding_v1 funding;
    uint8_t funding_root[32];
};

static bool patronage_store_binding(const char *workspace,
                                    const uint8_t network[32],
                                    uint8_t zid_seed_value,
                                    uint8_t zcl_value,
                                    uint8_t zid_pubkey[32],
                                    uint8_t zid_secret[32],
                                    uint8_t root_out[32])
{
    uint8_t seed[32], zcl_secret[32];
    memset(seed, zid_seed_value, sizeof(seed));
    zcl_ed25519_keypair(zid_pubkey, zid_secret, seed);
    memset(zcl_secret, zcl_value, sizeof(zcl_secret));
    struct privkey secret;
    struct pubkey pubkey;
    memset(secret.vch, zcl_value, 32);
    secret.fValid = true;
    secret.fCompressed = true;
    if (!privkey_get_pubkey(&secret, &pubkey) ||
        pubkey.size != COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    struct vcs_zcode_contributor_binding_v1 binding;
    memset(&binding, 0, sizeof(binding));
    binding.schema_version = VCS_ZCODE_CONTRIBUTOR_BINDING_VERSION;
    memcpy(binding.network_genesis_root, network, 32);
    memcpy(binding.zid_pubkey, zid_pubkey, 32);
    memcpy(binding.zcl_pubkey, pubkey.vch, 33);
    struct key_id key_id = pubkey_get_id(&pubkey);
    memcpy(binding.zcl_key_id, key_id.id.data, 20);
    binding.sequence = 1;
    binding.issued_unix = 100;
    binding.expires_unix = 1000000;
    binding.operation = VCS_ZCODE_BINDING_ACTIVE;
    if (vcs_zcode_contributor_binding_seal(
            &binding, zid_secret, zid_pubkey, zcl_secret) !=
        VCS_ZCODE_BINDING_OK)
        return false;
    uint8_t wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
    if (vcs_zcode_contributor_binding_root(&binding, root_out) !=
            VCS_ZCODE_BINDING_OK ||
        vcs_zcode_contributor_binding_serialize(&binding, wire) !=
            VCS_ZCODE_BINDING_OK)
        return false;
    return vcs_object_put_addressed(workspace, root_out, wire, sizeof(wire));
}

static bool patronage_lifecycle_build(struct patronage_lifecycle *life)
{
    memset(life, 0, sizeof(*life));
    test_make_tmpdir(life->workspace, sizeof(life->workspace),
                     "zcode_patronage_life", "cas");
    if (!vcs_object_store_init(life->workspace))
        return false;
    patronage_fill(life->network, 0xc1);
    uint8_t recipient_pubkey[32], recipient_secret[32];
    if (!patronage_store_binding(life->workspace, life->network, 0x41, 0x42,
                                 life->patron_pubkey, life->patron_secret,
                                 life->patron_binding_root) ||
        !patronage_store_binding(life->workspace, life->network, 0x43, 0x44,
                                 recipient_pubkey, recipient_secret,
                                 life->recipient_binding_root))
        return false;
    patronage_gift_intent(&life->intent, life->network,
                          life->patron_binding_root, life->patron_pubkey,
                          life->recipient_binding_root,
                          VCS_ZCODE_PATRONAGE_SIMULATED_FUNDING);
    if (vcs_zcode_patronage_intent_seal(
            &life->intent, life->patron_secret, life->patron_pubkey) !=
        VCS_ZCODE_PATRONAGE_OK)
        return false;
    uint8_t intent_wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
    if (vcs_zcode_patronage_intent_root(&life->intent, life->intent_root) !=
            VCS_ZCODE_PATRONAGE_OK ||
        vcs_zcode_patronage_intent_serialize(&life->intent, intent_wire) !=
            VCS_ZCODE_PATRONAGE_OK ||
        !vcs_object_put_addressed(life->workspace, life->intent_root,
                                  intent_wire, sizeof(intent_wire)))
        return false;
    patronage_funding_fixture(&life->funding, life->network,
                              life->intent_root, life->patron_binding_root,
                              life->patron_pubkey);
    if (vcs_zcode_patronage_funding_seal(
            &life->funding, life->patron_secret, life->patron_pubkey) !=
        VCS_ZCODE_PATRONAGE_FUNDING_OK)
        return false;
    uint8_t funding_wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
    if (vcs_zcode_patronage_funding_root(&life->funding,
                                         life->funding_root) !=
            VCS_ZCODE_PATRONAGE_FUNDING_OK ||
        vcs_zcode_patronage_funding_serialize(&life->funding, funding_wire) !=
            VCS_ZCODE_PATRONAGE_FUNDING_OK ||
        !vcs_object_put_addressed(life->workspace, life->funding_root,
                                  funding_wire, sizeof(funding_wire)))
        return false;
    return true;
}

static void patronage_gift_settlement(
    struct vcs_zcode_patronage_settlement_v1 *settlement,
    const struct patronage_lifecycle *life)
{
    memset(settlement, 0, sizeof(*settlement));
    settlement->schema_version = VCS_ZCODE_PATRONAGE_SETTLEMENT_VERSION;
    settlement->action = VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED;
    settlement->flags = VCS_ZCODE_PATRONAGE_SETTLEMENT_SIMULATION_ONLY |
        VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS |
        VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_TRANSACTION_BYTES;
    memcpy(settlement->network_genesis_root, life->network, 32);
    memcpy(settlement->patronage_intent_root, life->intent_root, 32);
    memcpy(settlement->patronage_funding_root, life->funding_root, 32);
    memcpy(settlement->recipient_contributor_binding_root,
           life->recipient_binding_root, 32);
    memcpy(settlement->settler_zid_pubkey, life->patron_pubkey, 32);
    settlement->amount_atoms = PATRONAGE_GIFT_AMOUNT;
    settlement->created_unix = 1700;
    settlement->observed_height = 100;
    settlement->observed_mtp = 1600;
    settlement->sequence = 1;
}

static int patronage_settlement_lifecycle_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage settlement: simulated lifecycle, live paths closed") {
        struct patronage_lifecycle life;
        ASSERT(patronage_lifecycle_build(&life));
        struct vcs_zcode_patronage_validation_context context = {
            .workspace = life.workspace,
            .expected_network_genesis_root = life.network,
            .now_unix = 1500,
        };
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(
                      &life.intent, &context),
                  VCS_ZCODE_PATRONAGE_OK);
        uint8_t other_network[32];
        patronage_fill(other_network, 0xc2);
        context.expected_network_genesis_root = other_network;
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(
                      &life.intent, &context),
                  VCS_ZCODE_PATRONAGE_NETWORK);
        context.expected_network_genesis_root = life.network;
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(
                      &life.funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);

        /* Funding against the intent fails closed on amount and timing. */
        struct vcs_zcode_patronage_funding_v1 funding = life.funding;
        funding.amount_atoms = PATRONAGE_GIFT_AMOUNT + 1;
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      life.intent_root, funding.amount_atoms,
                      funding.simulation_plan_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(
                      &funding, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(&funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT);
        funding = life.funding;
        funding.created_unix = 500; /* before the intent existed */
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(
                      &funding, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(&funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_TIME);

        struct vcs_zcode_patronage_settlement_v1 settlement;
        patronage_gift_settlement(&settlement, &life);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        struct vcs_zcode_patronage_settlement_validation_context
            settlement_context = {
                .patronage = &context,
                .creation = NULL,
                .active_height = 200,
                .active_mtp = 1650,
                .now_unix = 1700,
            };
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);

        /* Every deviation from the simulated gift fails closed with its own
         * typed error — none can move or imply live funds. */
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(&settlement,
                                                            NULL),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT);
        settlement_context.active_height = 0;
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT);
        settlement_context.active_height = 200;

        struct vcs_zcode_patronage_settlement_v1 mutated = settlement;
        mutated.created_unix = 1701; /* after the chain's now */
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME);

        mutated = settlement;
        mutated.observed_height = 201; /* above the active chain */
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME);

        mutated = settlement;
        mutated.created_unix = 1500; /* not after the funding receipt */
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME);

        mutated = settlement;
        mutated.amount_atoms = PATRONAGE_GIFT_AMOUNT + 1;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_AMOUNT);

        mutated = settlement;
        memcpy(mutated.patronage_funding_root, life.intent_root, 32);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_FUNDING);

        mutated = settlement;
        mutated.created_unix = 2000; /* offer already expired */
        settlement_context.now_unix = 2000;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT);
        settlement_context.now_unix = 1700;

        mutated = settlement;
        memcpy(mutated.recipient_contributor_binding_root,
               life.patron_binding_root, 32);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT);

        mutated = settlement;
        mutated.action = VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &mutated, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &mutated, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT);

        /* A gift carrying a proof chain is not even wire-canonical. */
        patronage_gift_settlement(&settlement, &life);
        patronage_fill(settlement.task_root, 64);
        ASSERT_EQ(vcs_zcode_patronage_settlement_validate(&settlement),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE);
        test_rm_rf(life.workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int patronage_projection_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage projection: CAS rebuild arithmetic is deterministic") {
        ASSERT(vcs_zcode_patronage_projection_build(NULL) == NULL);
        uint8_t network[32];
        patronage_fill(network, 0xc1);
        struct vcs_zcode_patronage_validation_context context = {
            .workspace = "./test-tmp",
            .expected_network_genesis_root = network,
            .now_unix = 0,
        };
        ASSERT(vcs_zcode_patronage_projection_build(&context) == NULL);

        char absent[256];
        test_fmt_tmpdir(absent, sizeof(absent),
                        "zcode_patronage_projection", "absent");
        test_rm_rf(absent);
        ASSERT(access(absent, F_OK) != 0);
        context.workspace = absent;
        context.now_unix = 1700;
        struct vcs_zcode_patronage_projection *empty_first =
            vcs_zcode_patronage_projection_build(&context);
        struct vcs_zcode_patronage_projection *empty_second =
            vcs_zcode_patronage_projection_build(&context);
        ASSERT(empty_first && empty_second);
        ASSERT(access(absent, F_OK) != 0);
        ASSERT(vcs_zcode_patronage_projection_count(empty_first) == 0);
        ASSERT(vcs_zcode_patronage_projection_at(empty_first, 0) == NULL);
        uint8_t failure_root[32];
        const char *failure_reason = NULL;
        ASSERT(!vcs_zcode_patronage_projection_first_failure(
                   empty_first, failure_root, &failure_reason));
        uint8_t empty_root_a[32], empty_root_b[32];
        ASSERT(vcs_zcode_patronage_projection_root(
                   empty_first, empty_root_a));
        ASSERT(vcs_zcode_patronage_projection_root(
                   empty_second, empty_root_b));
        ASSERT(memcmp(empty_root_a, empty_root_b, 32) == 0);
        vcs_zcode_patronage_projection_free(empty_second);
        vcs_zcode_patronage_projection_free(empty_first);

        struct patronage_lifecycle life;
        ASSERT(patronage_lifecycle_build(&life));
        context.workspace = life.workspace;
        context.expected_network_genesis_root = life.network;
        struct vcs_zcode_patronage_projection *first =
            vcs_zcode_patronage_projection_build(&context);
        struct vcs_zcode_patronage_projection *second =
            vcs_zcode_patronage_projection_build(&context);
        ASSERT(first && second);
        ASSERT(vcs_zcode_patronage_projection_count(first) == 2);
        const struct vcs_zcode_patronage_projection_entry *offer = NULL;
        const struct vcs_zcode_patronage_projection_entry *funding = NULL;
        const struct vcs_zcode_patronage_projection_entry *previous = NULL;
        for (size_t i = 0; i < 2; i++) {
            const struct vcs_zcode_patronage_projection_entry *entry =
                vcs_zcode_patronage_projection_at(first, i);
            ASSERT(entry != NULL);
            if (previous)
                ASSERT(memcmp(previous->root, entry->root, 32) < 0);
            previous = entry;
            if (entry->kind == VCS_ZCODE_PATRONAGE_PROJECTION_OFFER)
                offer = entry;
            if (entry->kind == VCS_ZCODE_PATRONAGE_PROJECTION_SIMULATED_FUNDING)
                funding = entry;
        }
        ASSERT(offer && funding);
        ASSERT(memcmp(offer->root, life.intent_root, 32) == 0);
        ASSERT(memcmp(offer->target_root, life.recipient_binding_root,
                      32) == 0);
        ASSERT(offer->amount_atoms == PATRONAGE_GIFT_AMOUNT);
        ASSERT(offer->created_unix == 1000);
        ASSERT(offer->expires_unix == 2000);
        ASSERT(memcmp(funding->root, life.funding_root, 32) == 0);
        ASSERT(memcmp(funding->target_root, life.intent_root, 32) == 0);
        ASSERT(funding->amount_atoms == PATRONAGE_GIFT_AMOUNT);
        ASSERT(funding->created_unix == 1500);
        ASSERT(funding->expires_unix == 0);
        ASSERT(!vcs_zcode_patronage_projection_first_failure(
                   first, failure_root, &failure_reason));
        uint8_t first_root[32], second_root[32];
        ASSERT(vcs_zcode_patronage_projection_root(first, first_root));
        ASSERT(vcs_zcode_patronage_projection_root(second, second_root));
        ASSERT(memcmp(first_root, second_root, 32) == 0);
        vcs_zcode_patronage_projection_free(second);
        vcs_zcode_patronage_projection_free(first);

        /* A misaddressed object is an integrity failure, never an entry. */
        uint8_t funding_wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_patronage_funding_serialize(
                      &life.funding, funding_wire),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        uint8_t bogus_root[32];
        patronage_fill(bogus_root, 0x77);
        ASSERT(memcmp(bogus_root, life.funding_root, 32) != 0);
        ASSERT(vcs_object_put_addressed(life.workspace, bogus_root,
                                        funding_wire, sizeof(funding_wire)));
        struct vcs_zcode_patronage_projection *flagged =
            vcs_zcode_patronage_projection_build(&context);
        ASSERT(flagged);
        ASSERT(vcs_zcode_patronage_projection_count(flagged) == 2);
        ASSERT(vcs_zcode_patronage_projection_first_failure(
                   flagged, failure_root, &failure_reason));
        ASSERT(memcmp(failure_root, bogus_root, 32) == 0);
        ASSERT_STR_EQ(failure_reason, "funding-authority");
        vcs_zcode_patronage_projection_free(flagged);
        test_rm_rf(life.workspace);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the CLI path: settle/refund leaves through the registry ─────────────
 *
 * The four settle/refund leaves were promoted from PLANNED fail-closed to
 * simulation-READY by binding the caller-pinned simulation context
 * (immutable policy root, declared anchors, CAS-derived uniqueness) the
 * settlement verifier demands. This block drives the promoted leaves
 * through zcl_command_registry_input_validate plus the real handlers: the
 * happy simulation settle and refund, and every fail-closed deviation —
 * missing immutable-policy context, a stale active-chain anchor, a
 * duplicate continuity event, and a live-money attempt refused by typed
 * wire shape. */

#include "command/native_command.h"
#include "command/native_zcode_patronage_priv.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "json/json.h"
#include "base/hex.h"
#include "vcs/zcode_dev.h"

struct patronage_cli {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void patronage_cli_init(struct patronage_cli *cli)
{
    json_init(&cli->input);
    json_set_object(&cli->input);
    memset(&cli->request, 0, sizeof(cli->request));
    cli->request.input = &cli->input;
    zcl_command_reply_init(&cli->reply, "zcl.patronage_cli_test.v1");
}

static void patronage_cli_free(struct patronage_cli *cli)
{
    zcl_command_reply_free(&cli->reply);
    json_free(&cli->input);
}

static const struct zcl_command_spec *patronage_leaf(const char *path)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    if (!registry) return NULL;
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->commands[i].path, path) == 0)
            return &registry->commands[i];
    return NULL;
}

static void patronage_settlement_hex(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    char out[2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES + 1])
{
    uint8_t wire[VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES];
    memset(out, 0, 2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES + 1);
    if (vcs_zcode_patronage_settlement_serialize(settlement, wire) ==
        VCS_ZCODE_PATRONAGE_SETTLEMENT_OK)
        zcl_hex_encode(wire, sizeof(wire), out);
}

/* The full caller-pinned simulation context the settle leaves require:
 * immutable policy root, expected epoch/award, active-chain height/MTP and
 * both declared anchors (numeric pins are decimal strings; now_unix is the
 * registry-typed integer). */
/* `skip_key` omits one pin (platform/modules/json has no remove); the two height strings
 * let a case pin a stale chain/anchor without re-pushing keys. */
static void patronage_settle_pins_v(struct json_value *input,
                                    const uint8_t network[32],
                                    const char *skip_key,
                                    const char *active_height,
                                    const char *anchor_maturity_height)
{
    uint8_t root[32];
    char hex[65];
#define PATRONAGE_PIN_STR(key, value)                                          \
    do {                                                                       \
        if (skip_key == NULL || strcmp(key, skip_key) != 0)                    \
            (void)json_push_kv_str(input, key, value);                         \
    } while (0)
    zcl_hex_encode(network, 32, hex);
    PATRONAGE_PIN_STR("expected_network_genesis_root", hex);
    patronage_fill(root, 0xd1);
    zcl_hex_encode(root, 32, hex);
    PATRONAGE_PIN_STR("expected_zc23_policy_root", hex);
    PATRONAGE_PIN_STR("expected_epoch", "1");
    PATRONAGE_PIN_STR("expected_award_atoms", "500000000");
    PATRONAGE_PIN_STR("active_height", active_height);
    PATRONAGE_PIN_STR("active_mtp", "1650");
    PATRONAGE_PIN_STR("anchor_opening_height", "100");
    patronage_fill(root, 0xa1);
    zcl_hex_encode(root, 32, hex);
    PATRONAGE_PIN_STR("anchor_opening_hash", hex);
    PATRONAGE_PIN_STR("anchor_maturity_height", anchor_maturity_height);
    patronage_fill(root, 0xa2);
    zcl_hex_encode(root, 32, hex);
    PATRONAGE_PIN_STR("anchor_maturity_hash", hex);
#undef PATRONAGE_PIN_STR
    (void)json_push_kv_int(input, "now_unix", 1700);
}

static void patronage_settle_pins(struct json_value *input,
                                  const uint8_t network[32])
{
    patronage_settle_pins_v(input, network, NULL, "200", "200");
}

static bool patronage_store_proof_policy(const char *workspace,
                                         uint8_t policy_root[32])
{
    struct vcs_zcode_proof_policy_v1 policy;
    memset(&policy, 0, sizeof(policy));
    policy.schema_version = VCS_ZCODE_DEV_VERSION;
    policy.required_proofs = VCS_ZCODE_PROOF_COMPILE | VCS_ZCODE_PROOF_TEST;
    policy.minimum_compile_receipts = 1;
    policy.minimum_test_receipts = 1;
    policy.minimum_matching_receipts = 1;
    policy.maximum_proof_age_seconds = 86400;
    uint8_t wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    return vcs_zcode_proof_policy_root(&policy, policy_root) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_serialize(&policy, wire) == VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, policy_root, wire, sizeof(wire));
}

static bool patronage_store_task(const char *workspace, uint8_t fill_base,
                                 const uint8_t proof_policy_root[32],
                                 uint8_t task_root[32])
{
    struct vcs_zcode_task_v1 task;
    memset(&task, 0, sizeof(task));
    task.schema_version = VCS_ZCODE_DEV_VERSION;
    patronage_fill(task.source_root, fill_base);
    patronage_fill(task.dependency_lock_root, (uint8_t)(fill_base + 1));
    patronage_fill(task.toolchain_capsule_root, (uint8_t)(fill_base + 2));
    patronage_fill(task.write_scope_root, (uint8_t)(fill_base + 3));
    patronage_fill(task.acceptance_tests_root, (uint8_t)(fill_base + 4));
    memcpy(task.proof_policy_root, proof_policy_root, 32);
    patronage_fill(task.model_policy_root, (uint8_t)(fill_base + 5));
    patronage_fill(task.goal_root, (uint8_t)(fill_base + 6));
    task.capabilities = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                        VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    task.max_changed_files = 8;
    task.max_patch_bytes = 65536;
    task.max_context_bytes = 65536;
    task.max_cpu_seconds = 60;
    task.max_memory_bytes = UINT64_C(16777216);
    task.max_output_bytes = 65536;
    task.expires_unix = 1000000;
    uint8_t wire[VCS_ZCODE_TASK_WIRE_BYTES];
    return vcs_zcode_task_root(&task, task_root) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_serialize(&task, wire) == VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, task_root, wire, sizeof(wire));
}

/* A task-commission lifecycle: the intent carries a refund schedule and its
 * task + proof policy are really in the CAS, so a REFUNDED settlement can
 * verify end to end. */
static bool patronage_commission_lifecycle_build(
    struct patronage_lifecycle *life)
{
    memset(life, 0, sizeof(*life));
    test_make_tmpdir(life->workspace, sizeof(life->workspace),
                     "zcode_patronage_refund", "cas");
    if (!vcs_object_store_init(life->workspace))
        return false;
    patronage_fill(life->network, 0xc1);
    uint8_t recipient_pubkey[32], recipient_secret[32];
    if (!patronage_store_binding(life->workspace, life->network, 0x41, 0x42,
                                 life->patron_pubkey, life->patron_secret,
                                 life->patron_binding_root) ||
        !patronage_store_binding(life->workspace, life->network, 0x43, 0x44,
                                 recipient_pubkey, recipient_secret,
                                 life->recipient_binding_root))
        return false;
    uint8_t policy_root[32], task_root[32];
    if (!patronage_store_proof_policy(life->workspace, policy_root) ||
        !patronage_store_task(life->workspace, 0x51, policy_root, task_root))
        return false;
    struct vcs_zcode_patronage_intent_v1 *intent = &life->intent;
    memset(intent, 0, sizeof(*intent));
    intent->schema_version = VCS_ZCODE_PATRONAGE_INTENT_VERSION;
    intent->mode = VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION;
    intent->target_kind = VCS_ZCODE_PATRONAGE_TARGET_TASK;
    intent->settlement_trust_mode = VCS_ZCODE_PATRONAGE_SIMULATED_FUNDING;
    intent->flags = VCS_ZCODE_PATRONAGE_NO_AUTHORITY |
                    VCS_ZCODE_PATRONAGE_SIMULATION_ONLY;
    memcpy(intent->network_genesis_root, life->network, 32);
    patronage_fill(intent->zc23_token_or_simulation_root, 32);
    memcpy(intent->patron_contributor_binding_root,
           life->patron_binding_root, 32);
    memcpy(intent->patron_zid_pubkey, life->patron_pubkey, 32);
    memcpy(intent->target_root, task_root, 32);
    memcpy(intent->task_root, task_root, 32);
    memcpy(intent->proof_policy_root, policy_root, 32);
    memcpy(intent->intended_recipient_binding_root,
           life->recipient_binding_root, 32);
    intent->amount_atoms = PATRONAGE_GIFT_AMOUNT;
    intent->created_unix = 1000;
    intent->expires_unix = 2000;
    intent->refund_height = 150;
    intent->refund_unix = 2100;
    intent->sequence = 1;
    intent->maximum_zcl_fee_zat = 10000;
    if (vcs_zcode_patronage_intent_seal(
            intent, life->patron_secret, life->patron_pubkey) !=
        VCS_ZCODE_PATRONAGE_OK)
        return false;
    uint8_t intent_wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
    if (vcs_zcode_patronage_intent_root(intent, life->intent_root) !=
            VCS_ZCODE_PATRONAGE_OK ||
        vcs_zcode_patronage_intent_serialize(intent, intent_wire) !=
            VCS_ZCODE_PATRONAGE_OK ||
        !vcs_object_put_addressed(life->workspace, life->intent_root,
                                  intent_wire, sizeof(intent_wire)))
        return false;
    patronage_funding_fixture(&life->funding, life->network,
                              life->intent_root, life->patron_binding_root,
                              life->patron_pubkey);
    if (vcs_zcode_patronage_funding_seal(
            &life->funding, life->patron_secret, life->patron_pubkey) !=
        VCS_ZCODE_PATRONAGE_FUNDING_OK)
        return false;
    uint8_t funding_wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
    if (vcs_zcode_patronage_funding_root(&life->funding,
                                         life->funding_root) !=
            VCS_ZCODE_PATRONAGE_FUNDING_OK ||
        vcs_zcode_patronage_funding_serialize(&life->funding, funding_wire) !=
            VCS_ZCODE_PATRONAGE_FUNDING_OK ||
        !vcs_object_put_addressed(life->workspace, life->funding_root,
                                  funding_wire, sizeof(funding_wire)))
        return false;
    return true;
}

static void patronage_refund_settlement(
    struct vcs_zcode_patronage_settlement_v1 *settlement,
    const struct patronage_lifecycle *life)
{
    memset(settlement, 0, sizeof(*settlement));
    settlement->schema_version = VCS_ZCODE_PATRONAGE_SETTLEMENT_VERSION;
    settlement->action = VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED;
    settlement->flags = VCS_ZCODE_PATRONAGE_SETTLEMENT_SIMULATION_ONLY |
        VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS |
        VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_TRANSACTION_BYTES;
    memcpy(settlement->network_genesis_root, life->network, 32);
    memcpy(settlement->patronage_intent_root, life->intent_root, 32);
    memcpy(settlement->patronage_funding_root, life->funding_root, 32);
    /* A refund returns to the patron, not the intended recipient. */
    memcpy(settlement->recipient_contributor_binding_root,
           life->patron_binding_root, 32);
    memcpy(settlement->settler_zid_pubkey, life->patron_pubkey, 32);
    settlement->amount_atoms = PATRONAGE_GIFT_AMOUNT;
    settlement->created_unix = 2100;
    settlement->observed_height = 150;
    settlement->observed_mtp = 2100;
    settlement->sequence = 1;
}

/* Two same-event continuity attributions: identical event tuple (category
 * class, task, score receipt, package, release) but different epochs, so
 * their roots differ while the continuity event key collides. */
static void patronage_event_attribution(
    struct vcs_zcode_creation_attribution_v1 *a, uint16_t category,
    uint64_t epoch, uint8_t package_fill)
{
    memset(a, 0, sizeof(*a));
    a->schema_version = VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
    a->category = category;
    a->lineage_kind = VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY;
    a->epoch = epoch;
    a->award_atoms = UINT64_C(100000000);
    a->challenge_opening_height = 100;
    patronage_fill(a->challenge_opening_hash, 0xe1);
    a->challenge_opening_mtp = 1000;
    a->challenge_maturity_height = 8164;
    a->challenge_maturity_mtp = 605800;
    a->created_unix = 605801;
    patronage_fill(a->network_genesis_root, 0xe2);
    patronage_fill(a->zc23_policy_root, 0xe3);
    patronage_fill(a->contributor_binding_root, 0xe4);
    patronage_fill(a->task_root, 0xe5);
    patronage_fill(a->candidate_root, 0xe6);
    patronage_fill(a->proof_policy_root, 0xe7);
    patronage_fill(a->proof_set_root, 0xe8);
    patronage_fill(a->proven_lane_root, 0xe9);
    patronage_fill(a->score_receipt_root, 0xea);
    patronage_fill(a->package_root, package_fill);
    patronage_fill(a->release_root, 0xec);
    patronage_fill(a->license_evidence_root, 0xed);
    patronage_fill(a->lineage_root, 0xee);
}

static bool patronage_store_attribution(
    const char *workspace,
    const struct vcs_zcode_creation_attribution_v1 *a, uint8_t root_out[32])
{
    uint8_t wire[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
    return vcs_zcode_creation_attribution_serialize(a, wire) ==
            VCS_ZCODE_CREATION_OK &&
        vcs_zcode_creation_attribution_root(a, root_out) ==
            VCS_ZCODE_CREATION_OK &&
        vcs_object_put_addressed(workspace, root_out, wire, sizeof(wire));
}

static int patronage_settlement_cli_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage settle/refund: promoted leaves fail closed only on typed deviations") {
        const struct zcl_command_spec *settle_plan =
            patronage_leaf("zcode.patronage.settle.plan");
        const struct zcl_command_spec *settle_commit =
            patronage_leaf("zcode.patronage.settle.commit");
        const struct zcl_command_spec *refund_plan =
            patronage_leaf("zcode.patronage.refund.plan");
        const struct zcl_command_spec *refund_commit =
            patronage_leaf("zcode.patronage.refund.commit");
        ASSERT(settle_plan && settle_commit && refund_plan && refund_commit);
        ASSERT(settle_plan->availability == ZCL_COMMAND_READY &&
               settle_commit->availability == ZCL_COMMAND_READY &&
               refund_plan->availability == ZCL_COMMAND_READY &&
               refund_commit->availability == ZCL_COMMAND_READY);
        ASSERT(settle_plan->handler ==
                   zcl_native_handle_zcode_patronage_settle_plan &&
               settle_commit->handler ==
                   zcl_native_handle_zcode_patronage_settle_commit &&
               refund_plan->handler ==
                   zcl_native_handle_zcode_patronage_refund_plan &&
               refund_commit->handler ==
                   zcl_native_handle_zcode_patronage_refund_commit);

        struct patronage_lifecycle life;
        ASSERT(patronage_lifecycle_build(&life));
        struct vcs_zcode_patronage_settlement_v1 settlement;
        patronage_gift_settlement(&settlement, &life);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        char settle_hex[2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES + 1];
        patronage_settlement_hex(&settlement, settle_hex);
        ASSERT(strlen(settle_hex) ==
               2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES);

        char why[192] = {0};
        struct patronage_cli cli;

        /* The validator accepts exactly the declared keys. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", settle_hex);
        patronage_settle_pins(&cli.input, life.network);
        ASSERT(zcl_command_registry_input_validate(settle_plan, &cli.input,
                                                   why, sizeof(why)));
        settle_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&cli.reply.data, "simulation_only")));
        ASSERT(!json_get_bool(json_get(&cli.reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&cli.reply.data, "moves_live_funds")));
        ASSERT(!json_get_bool(json_get(&cli.reply.data, "implies_custody")));
        ASSERT_STR_EQ(json_get_str(json_get(&cli.reply.data, "action")),
                      "simulated_settled");
        ASSERT_STR_EQ(
            json_get_str(json_get(&cli.reply.data, "validation_authority")),
            "caller_pinned_simulation_context");
        cli.request.spec = settle_plan;
        cli.request.invoked_name = settle_plan->path;
        patronage_cli_free(&cli);

        /* Commit persists the verified wire idempotently. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", settle_hex);
        patronage_settle_pins(&cli.input, life.network);
        ASSERT(zcl_command_registry_input_validate(settle_commit, &cli.input,
                                                   why, sizeof(why)));
        settle_commit->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&cli.reply.data, "persisted")));
        const char *stored_hex = json_get_str(
            json_get(&cli.reply.data, "patronage_settlement_root"));
        ASSERT(stored_hex && strlen(stored_hex) == 64);
        uint8_t stored_root[32], *stored_wire = NULL;
        size_t stored_len = 0;
        ASSERT(zcl_hex_decode_lower(stored_hex, stored_root, 32));
        patronage_cli_free(&cli);
        ASSERT(vcs_object_load_raw_bounded(
                   life.workspace, stored_root,
                   VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES, &stored_wire,
                   &stored_len) == 0);
        ASSERT(stored_len == VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES);
        free(stored_wire);
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", settle_hex);
        patronage_settle_pins(&cli.input, life.network);
        settle_commit->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        patronage_cli_free(&cli);

        /* An undeclared key is refused by the validator, not the handler. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", settle_hex);
        patronage_settle_pins(&cli.input, life.network);
        (void)json_push_kv_str(&cli.input, "broadcast", "true");
        why[0] = '\0';
        ASSERT(!zcl_command_registry_input_validate(settle_plan, &cli.input,
                                                    why, sizeof(why)) &&
               why[0] != '\0');
        patronage_cli_free(&cli);

        /* Missing immutable-policy context: the validator's closed set does
         * not require pins, so the handler itself must fail closed. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", settle_hex);
        patronage_settle_pins_v(&cli.input, life.network,
                                "expected_zc23_policy_root", "200", "200");
        ASSERT(zcl_command_registry_input_validate(settle_plan, &cli.input,
                                                   why, sizeof(why)));
        settle_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(cli.reply.error.code, "PATRONAGE_SETTLE_REFUSED");
        patronage_cli_free(&cli);

        /* Stale active-chain anchor: a declared maturity anchor above the
         * pinned active tip is an inconsistent context, refused by name. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", settle_hex);
        patronage_settle_pins_v(&cli.input, life.network, NULL, "200", "300");
        settle_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(cli.reply.error.code, "PATRONAGE_SETTLE_REFUSED");
        ASSERT(strstr(cli.reply.error.message, "anchor") != NULL);
        patronage_cli_free(&cli);

        /* Stale chain authority: an active tip pinned below the declared
         * simulation anchors (opening 100) can never form a consistent
         * context, so the refusal names the anchor/tip inconsistency at
         * bind time, before any settlement fact is trusted. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", settle_hex);
        patronage_settle_pins_v(&cli.input, life.network, NULL, "99", "99");
        settle_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(cli.reply.error.code, "PATRONAGE_SETTLE_REFUSED");
        ASSERT_STR_EQ(cli.reply.error.message,
                      "declared anchors are above the active-chain tip");
        patronage_cli_free(&cli);

        /* A live-money attempt is refused by typed wire shape: clearing the
         * mandatory simulation-only/no-live-funds flags is not parseable. */
        uint8_t live_wire[VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_patronage_settlement_serialize(&settlement,
                                                           live_wire),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        live_wire[11] = 0; /* flags: simulation bits cleared */
        char live_hex[2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES + 1];
        zcl_hex_encode(live_wire, sizeof(live_wire), live_hex);
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", live_hex);
        patronage_settle_pins(&cli.input, life.network);
        settle_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(cli.reply.error.code, "PATRONAGE_SETTLE_REFUSED");
        ASSERT_STR_EQ(cli.reply.error.message, "simulation-shape");
        patronage_cli_free(&cli);

        /* A refund wire on the settle leaf is an action mismatch. */
        struct patronage_lifecycle refund_life;
        ASSERT(patronage_commission_lifecycle_build(&refund_life));
        struct vcs_zcode_patronage_settlement_v1 refund;
        patronage_refund_settlement(&refund, &refund_life);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &refund, refund_life.patron_secret,
                      refund_life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        char refund_hex[2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES + 1];
        patronage_settlement_hex(&refund, refund_hex);
        ASSERT(strlen(refund_hex) ==
               2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES);
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", refund_life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", refund_hex);
        patronage_settle_pins(&cli.input, refund_life.network);
        settle_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(cli.reply.error.message, "settlement-action-mismatch");
        patronage_cli_free(&cli);

        /* Happy simulated refund through plan and commit. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", refund_life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", refund_hex);
        char hex[65];
        zcl_hex_encode(refund_life.network, 32, hex);
        (void)json_push_kv_str(&cli.input, "expected_network_genesis_root",
                               hex);
        (void)json_push_kv_str(&cli.input, "active_height", "200");
        (void)json_push_kv_str(&cli.input, "active_mtp", "2200");
        (void)json_push_kv_int(&cli.input, "now_unix", 2100);
        ASSERT(zcl_command_registry_input_validate(refund_plan, &cli.input,
                                                   why, sizeof(why)));
        refund_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&cli.reply.data, "action")),
                      "simulated_refunded");
        ASSERT(json_get_bool(json_get(&cli.reply.data, "simulated_refunded")));
        ASSERT(!json_get_bool(json_get(&cli.reply.data, "refunded")));
        patronage_cli_free(&cli);
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", refund_life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", refund_hex);
        zcl_hex_encode(refund_life.network, 32, hex);
        (void)json_push_kv_str(&cli.input, "expected_network_genesis_root",
                               hex);
        (void)json_push_kv_str(&cli.input, "active_height", "200");
        (void)json_push_kv_str(&cli.input, "active_mtp", "2200");
        (void)json_push_kv_int(&cli.input, "now_unix", 2100);
        ASSERT(zcl_command_registry_input_validate(refund_commit, &cli.input,
                                                   why, sizeof(why)));
        refund_commit->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&cli.reply.data, "persisted")));
        patronage_cli_free(&cli);

        /* A refund before the schedule matures fails with the TIME rung. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", refund_life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", refund_hex);
        zcl_hex_encode(refund_life.network, 32, hex);
        (void)json_push_kv_str(&cli.input, "expected_network_genesis_root",
                               hex);
        (void)json_push_kv_str(&cli.input, "active_height", "149");
        (void)json_push_kv_str(&cli.input, "active_mtp", "2200");
        (void)json_push_kv_int(&cli.input, "now_unix", 2100);
        refund_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(cli.reply.error.code, "PATRONAGE_REFUND_REFUSED");
        ASSERT_STR_EQ(cli.reply.error.message, "time-order");
        patronage_cli_free(&cli);
        test_rm_rf(refund_life.workspace);

        /* A gift refund can never verify: gift intents have no schedule. */
        struct vcs_zcode_patronage_settlement_v1 gift_refund = settlement;
        gift_refund.action = VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED;
        memcpy(gift_refund.recipient_contributor_binding_root,
               life.patron_binding_root, 32);
        gift_refund.created_unix = 2100;
        gift_refund.observed_mtp = 2100;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &gift_refund, life.patron_secret, life.patron_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        char gift_refund_hex[
            2 * VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES + 1];
        patronage_settlement_hex(&gift_refund, gift_refund_hex);
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", life.workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex",
                               gift_refund_hex);
        zcl_hex_encode(life.network, 32, hex);
        (void)json_push_kv_str(&cli.input, "expected_network_genesis_root",
                               hex);
        (void)json_push_kv_str(&cli.input, "active_height", "200");
        (void)json_push_kv_str(&cli.input, "active_mtp", "2200");
        (void)json_push_kv_int(&cli.input, "now_unix", 2100);
        refund_plan->handler(&cli.request, &cli.reply);
        ASSERT(cli.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(cli.reply.error.message, "intent-mismatch");
        patronage_cli_free(&cli);
        test_rm_rf(life.workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int patronage_uniqueness_callback_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage context: continuity-event uniqueness is CAS-derived") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_patronage_uniqueness", "cas");
        ASSERT(vcs_object_store_init(workspace));
        struct vcs_zcode_creation_attribution_v1 first, second, distinct;
        patronage_event_attribution(&first, VCS_ZCODE_CREATION_BORN_RED_FIX,
                                    7, 0xeb);
        patronage_event_attribution(&second, VCS_ZCODE_CREATION_BORN_RED_FIX,
                                    8, 0xeb);
        patronage_event_attribution(&distinct,
                                    VCS_ZCODE_CREATION_BORN_RED_FIX, 9, 0xf0);
        /* The fixture fills candidate_root with a constant, so give the
         * distinct attribution its own candidate root before it is
         * addressed and stored. */
        patronage_fill(distinct.candidate_root, 0xf2);
        uint8_t first_root[32], second_root[32], distinct_root[32];
        ASSERT(patronage_store_attribution(workspace, &first, first_root));
        ASSERT(patronage_store_attribution(workspace, &second, second_root));
        ASSERT(patronage_store_attribution(workspace, &distinct,
                                           distinct_root));
        ASSERT(memcmp(first_root, second_root, 32) != 0);

        /* Bind the exact context the settle handlers bind (priv seam). */
        uint8_t network[32];
        patronage_fill(network, 0xc1);
        struct patronage_cli cli;
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", workspace);
        (void)json_push_kv_str(&cli.input, "settlement_hex", "00");
        patronage_settle_pins(&cli.input, network);
        struct zpc_simulation_context bound;
        const char *bind_reason = NULL;
        ASSERT(zpc_simulation_context_bind(&cli.input, &bound,
                                           &bind_reason));
        patronage_cli_free(&cli);

        /* The declared anchors are the only active ones. */
        uint8_t opening_hash[32], foreign_hash[32];
        patronage_fill(opening_hash, 0xa1);
        patronage_fill(foreign_hash, 0xa9);
        ASSERT(bound.creation.anchor_is_active(
                   bound.creation.callback_opaque, 100, opening_hash));
        ASSERT(!bound.creation.anchor_is_active(
                   bound.creation.callback_opaque, 101, opening_hash));
        ASSERT(!bound.creation.anchor_is_active(
                   bound.creation.callback_opaque, 100, foreign_hash));

        /* A second attribution for the same continuity event is a duplicate;
         * a distinct package tuple and self-matching are not. */
        uint8_t any_key[32];
        patronage_fill(any_key, 0xf1);
        ASSERT(bound.creation.continuity_is_duplicate(
                   bound.creation.callback_opaque, any_key, first_root));
        ASSERT(!bound.creation.continuity_is_duplicate(
                   bound.creation.callback_opaque, any_key, distinct_root));

        /* One candidate root credits one contributor once: first and second
         * share a candidate root (they differ only in epoch), so each makes
         * the other a duplicate; a candidate root with no sibling attribution
         * (self excluded) and an unknown candidate root are not. */
        ASSERT(bound.creation.contribution_is_duplicate(
                   bound.creation.callback_opaque, first.candidate_root,
                   first_root));
        ASSERT(bound.creation.contribution_is_duplicate(
                   bound.creation.callback_opaque, first.candidate_root,
                   second_root));
        ASSERT(!bound.creation.contribution_is_duplicate(
                   bound.creation.callback_opaque, distinct.candidate_root,
                   distinct_root));
        uint8_t unknown_candidate[32];
        patronage_fill(unknown_candidate, 0xf7);
        ASSERT(!bound.creation.contribution_is_duplicate(
                   bound.creation.callback_opaque, unknown_candidate,
                   first_root));
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int patronage_commons_anchor_status_test(void)
{
    int failures = 0;
    TEST("ZC23 commons status: complete under verified anchors, else a named blocker") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_patronage_commons", "cas");
        ASSERT(vcs_object_store_init(workspace));
        struct patronage_cli cli;

        /* No context pins: honest status plus a NAMED blocker, never a
         * silent unknown. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", workspace);
        zcl_native_handle_zcode_commons_status(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!json_get_bool(
            json_get(&cli.reply.data, "anchor_context_bound")));
        ASSERT_STR_EQ(
            json_get_str(json_get(&cli.reply.data, "verification_blocker")),
            "simulation_anchor_context_not_supplied");
        patronage_cli_free(&cli);

        /* A partial pin set names its first missing pin. */
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", workspace);
        (void)json_push_kv_str(&cli.input, "active_height", "200");
        zcl_native_handle_zcode_commons_status(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        const char *blocker =
            json_get_str(json_get(&cli.reply.data, "verification_blocker"));
        ASSERT(blocker &&
               strstr(blocker, "missing_simulation_context_pin:") == blocker);
        patronage_cli_free(&cli);

        /* The full pin set over a sound projection reports complete. */
        uint8_t network[32];
        patronage_fill(network, 0xc1);
        patronage_cli_init(&cli);
        (void)json_push_kv_str(&cli.input, "workspace", workspace);
        patronage_settle_pins(&cli.input, network);
        zcl_native_handle_zcode_commons_status(&cli.request, &cli.reply);
        ASSERT(cli.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(
            json_get(&cli.reply.data, "anchor_context_bound")));
        ASSERT_STR_EQ(
            json_get_str(json_get(&cli.reply.data, "verification_status")),
            "complete");
        ASSERT(json_get_bool(
            json_get(&cli.reply.data, "policy_valid_minted_supply_known")));
        patronage_cli_free(&cli);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_patronage(void)
{
    return patronage_intent_gift_test() + patronage_funding_codec_test() +
           patronage_settlement_lifecycle_test() + patronage_projection_test() +
           patronage_settlement_cli_test() +
           patronage_uniqueness_callback_test() +
           patronage_commons_anchor_status_test();
}
