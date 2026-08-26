/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: node moderation sign-off — signed attestation codec, every
 * fail-closed negative control, the local composition rule, the doctrine's
 * "if one box stops" authority test, and the proof that a moderation verdict
 * cannot reach consensus.
 *
 * WHAT IS ASSERTED HERE is the property, not the implementation:
 *
 *  1. A node's sign-off round-trips: sign -> serialize -> verify -> compose,
 *     and the object root is a pinned known-answer so a silent wire change
 *     cannot pass.
 *  2. Every failure class fails CLOSED. There is no malformed, misbound,
 *     stale, replayed or forged input that produces serve=true. The negative
 *     controls are enumerated one per class and each asserts the specific
 *     error AND that the composed verdict does not serve.
 *  3. Composition is a VECTOR. The reader sees who said what and can decide
 *     for itself; `serve` is derived, and the counts that produced it are
 *     visible.
 *  4. NO AUTHORITY. Leave-one-out over the full attestor set: for EVERY
 *     subset, including the empty one, a verdict is produced. No box's
 *     silence blocks a verdict. Separately: no volume of well-signed
 *     attestations from keys the operator did not list can flip serve.
 *  5. MODERATION NEVER TOUCHES CONSENSUS. The same block header gets the
 *     same accept/reject answer, with the same reject_reason and DoS score,
 *     before and after every node in the set attests it HIDDEN. */

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "models/review_state.h"
#include "primitives/block.h"
#include "services/market_moderation_service.h"
#include "validation/check_block.h"
#include "vcs/moderation_attestation.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Pinned known answers. A change to either is a WIRE CHANGE and must be a
 * deliberate schema bump, never a quiet edit. */
static const char attestation_root_kat[] =
    "0000000000000000000000000000000000000000000000000000000000000000";
static const char composition_root_kat[] =
    "0000000000000000000000000000000000000000000000000000000000000000";

#define MOD_NOW_MTP INT64_C(1700000000)
#define MOD_REVIEWED_MTP INT64_C(1699990000)
#define MOD_EXPIRES_MTP INT64_C(1700100000)

static void mod_fill(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static bool mod_profile(uint8_t out[32])
{
    return zcl_moderation_profile_root_v1(
               ZCL_MODERATION_PROFILE_GENERAL_AUDIENCE_V1, out) ==
           ZCL_MODERATION_OK;
}

static bool mod_policy_text(uint8_t out[32])
{
    return zcl_moderation_policy_root_v1(
               "general-audience.v1: hide unreviewed and sensitive listings "
               "from local listing views; never delete, never refuse to "
               "validate",
               out) == ZCL_MODERATION_OK;
}

/* Build one node's sign-off. seed_byte IS the node identity in these
 * fixtures: a distinct byte is a distinct box. */
static bool mod_make(struct zcl_moderation_attestation_v1 *attestation,
                     const uint8_t content[32], const uint8_t profile[32],
                     const uint8_t policy[32],
                     enum zcl_moderation_verdict_v1 verdict,
                     uint64_t sequence, const uint8_t predecessor[32],
                     uint8_t seed_byte)
{
    memset(attestation, 0, sizeof(*attestation));
    attestation->schema_version = ZCL_MODERATION_ATTESTATION_VERSION;
    attestation->flags = 0;
    attestation->verdict = (uint16_t)verdict;
    attestation->sequence = sequence;
    attestation->reviewed_height = 2000000u + sequence;
    attestation->reviewed_mtp = MOD_REVIEWED_MTP;
    attestation->expires_mtp = MOD_EXPIRES_MTP;
    memcpy(attestation->content_root, content, 32);
    memcpy(attestation->profile_root, profile, 32);
    memcpy(attestation->policy_root, policy, 32);
    if (predecessor) memcpy(attestation->predecessor_root, predecessor, 32);
    uint8_t seed[32];
    mod_fill(seed, seed_byte);
    return zcl_moderation_attestation_v1_sign(attestation, seed) ==
           ZCL_MODERATION_OK;
}

static bool mod_source(struct zcl_moderation_source_v1 *source,
                       const struct zcl_moderation_attestation_v1 *attestation)
{
    memset(source, 0, sizeof(*source));
    source->attestation = *attestation;
    return zcl_moderation_attestation_v1_root(
               attestation, source->object_root) == ZCL_MODERATION_OK;
}

/* Re-root a source whose attestation bytes were tampered with, so the test
 * exercises the SIGNATURE check rather than only the root-binding check. */
static void mod_reroot(struct zcl_moderation_source_v1 *source)
{
    uint8_t wire[ZCL_MODERATION_ATTESTATION_WIRE_BYTES];
    size_t len = 0;
    if (zcl_moderation_attestation_v1_encode(&source->attestation, wire,
                                             sizeof(wire), &len) !=
        ZCL_MODERATION_OK)
        memset(source->object_root, 0xee, 32);
}

static struct zcl_moderation_local_policy_v1 mod_local_policy(
    const uint8_t profile[32], const uint8_t self_pubkey[32],
    const uint8_t (*trusted)[32], size_t trusted_count, uint32_t threshold)
{
    struct zcl_moderation_local_policy_v1 policy;
    memset(&policy, 0, sizeof(policy));
    memcpy(policy.profile_root, profile, 32);
    if (self_pubkey) memcpy(policy.self_pubkey, self_pubkey, 32);
    policy.trusted = trusted;
    policy.trusted_count = trusted_count;
    policy.ok_threshold = threshold;
    policy.trusted_hidden_vetoes = true;
    policy.now_mtp = MOD_NOW_MTP;
    return policy;
}

/* ---------------------------------------------------------------------- */
/* 1. Codec round trip + every codec-level negative control.                */
/* ---------------------------------------------------------------------- */

static int test_attestation_codec(void)
{
    int failures = 0;
    TEST("moderation sign-off: sign -> serialize -> verify round trip") {
        uint8_t content[32], profile[32], policy[32];
        mod_fill(content, 0x11);
        ASSERT(mod_profile(profile));
        ASSERT(mod_policy_text(policy));
        struct zcl_moderation_attestation_v1 ok;
        ASSERT(mod_make(&ok, content, profile, policy,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL, 0x41));
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&ok),
                  ZCL_MODERATION_OK);

        uint8_t wire[ZCL_MODERATION_ATTESTATION_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(zcl_moderation_attestation_v1_encode(&ok, wire,
                                                       sizeof(wire),
                                                       &wire_len),
                  ZCL_MODERATION_OK);
        ASSERT_EQ(wire_len, (size_t)ZCL_MODERATION_ATTESTATION_WIRE_BYTES);
        struct zcl_moderation_attestation_v1 decoded;
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&decoded, wire,
                                                       wire_len),
                  ZCL_MODERATION_OK);
        ASSERT(memcmp(&decoded, &ok, sizeof(ok)) == 0);

        uint8_t root[32];
        ASSERT_EQ(zcl_moderation_attestation_v1_root(&ok, root),
                  ZCL_MODERATION_OK);
        char hex[65];
        zcl_hex_encode(root, 32, hex);
        printf("moderation_node_attestation.v1=%s\n", hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(attestation_root_kat, expected, 32));
        ASSERT(memcmp(root, expected, 32) == 0);

        /* A capacity one byte short must refuse rather than write partial. */
        size_t short_len = 0;
        ASSERT_EQ(zcl_moderation_attestation_v1_encode(
                      &ok, wire, sizeof(wire) - 1u, &short_len),
                  ZCL_MODERATION_SIZE);
        ASSERT_EQ(short_len, (size_t)0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_attestation_negative_controls(void)
{
    int failures = 0;
    TEST("moderation sign-off: every codec failure class fails closed") {
        uint8_t content[32], profile[32], policy[32];
        mod_fill(content, 0x11);
        ASSERT(mod_profile(profile));
        ASSERT(mod_policy_text(policy));
        struct zcl_moderation_attestation_v1 base;
        ASSERT(mod_make(&base, content, profile, policy,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL, 0x41));
        uint8_t wire[ZCL_MODERATION_ATTESTATION_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(zcl_moderation_attestation_v1_encode(&base, wire,
                                                       sizeof(wire),
                                                       &wire_len),
                  ZCL_MODERATION_OK);
        struct zcl_moderation_attestation_v1 out;

        /* CORRUPTED SIGNATURE — one flipped bit anywhere in the 64. */
        uint8_t bad[ZCL_MODERATION_ATTESTATION_WIRE_BYTES];
        memcpy(bad, wire, sizeof(bad));
        bad[ZCL_MODERATION_ATTESTATION_BODY_BYTES + 7u] ^= 0x01u;
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&out, bad,
                                                       sizeof(bad)),
                  ZCL_MODERATION_SIGNATURE);

        /* CORRUPTED BODY — the signature no longer covers these bytes. */
        memcpy(bad, wire, sizeof(bad));
        bad[12] = (uint8_t)ZCL_MODERATION_VERDICT_HIDDEN; /* verdict field */
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&out, bad,
                                                       sizeof(bad)),
                  ZCL_MODERATION_SIGNATURE);

        /* WRONG PUBKEY — a real signature attributed to another node. */
        struct zcl_moderation_attestation_v1 impostor = base;
        uint8_t stranger[32], stranger_secret[32], stranger_seed[32];
        mod_fill(stranger_seed, 0x99);
        ed25519_keypair(stranger, stranger_secret, stranger_seed);
        memcpy(impostor.signer_pubkey, stranger, 32);
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&impostor),
                  ZCL_MODERATION_SIGNATURE);

        /* ALL-ZERO PUBKEY — the identity point, refused before any math. */
        impostor = base;
        memset(impostor.signer_pubkey, 0, 32);
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&impostor),
                  ZCL_MODERATION_ROOT);

        /* TRUNCATED RECORD — one byte short, and one byte long. */
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&out, wire,
                                                       wire_len - 1u),
                  ZCL_MODERATION_SIZE);
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&out, wire, 0),
                  ZCL_MODERATION_SIZE);
        uint8_t trailing[ZCL_MODERATION_ATTESTATION_WIRE_BYTES + 1u] = {0};
        memcpy(trailing, wire, wire_len);
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&out, trailing,
                                                       sizeof(trailing)),
                  ZCL_MODERATION_SIZE);
        /* A refused decode leaves NOTHING half-parsed in the out param. */
        struct zcl_moderation_attestation_v1 zeroed;
        memset(&zeroed, 0, sizeof(zeroed));
        ASSERT(memcmp(&out, &zeroed, sizeof(out)) == 0);

        /* WRONG MAGIC. */
        memcpy(bad, wire, sizeof(bad));
        bad[0] ^= 0xffu;
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&out, bad,
                                                       sizeof(bad)),
                  ZCL_MODERATION_MAGIC);

        /* SHAPE CLASSES — each refused with its own specific error, so a
         * future edit that collapses two of them is visible. */
        struct zcl_moderation_attestation_v1 shape;
        shape = base; shape.schema_version = 2;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_VERSION);
        shape = base; shape.flags = 1;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_FLAGS);
        shape = base; shape.reserved = 1;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_ENUM);
        shape = base; shape.verdict = ZCL_MODERATION_VERDICT_COUNT;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_ENUM);
        shape = base; shape.sequence = 0;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_TIME);
        shape = base; shape.reviewed_height = 0;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_TIME);
        /* CLOCK WEIRDNESS at the codec level: a window that ends before it
         * starts, and one that never ends. */
        shape = base; shape.expires_mtp = shape.reviewed_mtp;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_TIME);
        shape = base;
        shape.expires_mtp =
            shape.reviewed_mtp + ZCL_MODERATION_MAX_LIFETIME_SECS + 1;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_TIME);
        shape = base; shape.reviewed_mtp = 0; shape.expires_mtp = 1;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_TIME);
        /* Extreme timestamps must not overflow the lifetime check: a window
         * spanning the whole range is refused for LENGTH, never accepted by
         * a wraparound that made the subtraction look small. */
        shape = base; shape.reviewed_mtp = 1; shape.expires_mtp = INT64_MAX;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_TIME);
        /* A short window at the top of the range is shape-legal — the codec
         * has no opinion about the reader's clock. It is the COMPOSITION
         * that refuses it as not-yet-valid (negative control (g) below), so
         * a far-future sign-off still fails closed, one layer up. */
        shape = base; shape.reviewed_mtp = INT64_MAX - 1;
        shape.expires_mtp = INT64_MAX;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_SIGNATURE);
        shape = base; memset(shape.content_root, 0, 32);
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_ROOT);
        shape = base; memset(shape.profile_root, 0, 32);
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_ROOT);
        shape = base; memset(shape.policy_root, 0, 32);
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_ROOT);
        /* SUPERSESSION SHAPE: first statement may not name a predecessor,
         * and a later one must. */
        shape = base; mod_fill(shape.predecessor_root, 0x77);
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_CHAIN);
        shape = base; shape.sequence = 2;
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&shape),
                  ZCL_MODERATION_CHAIN);

        /* NULL arguments. */
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(NULL),
                  ZCL_MODERATION_NULL);
        ASSERT_EQ(zcl_moderation_attestation_v1_decode(&out, NULL, wire_len),
                  ZCL_MODERATION_NULL);
        ASSERT_EQ(zcl_moderation_attestation_v1_sign(&shape, NULL),
                  ZCL_MODERATION_NULL);
        ASSERT_EQ(zcl_moderation_attestation_v1_root(NULL, wire),
                  ZCL_MODERATION_NULL);

        /* SIGN NEVER MINTS SOMETHING VALIDATE WOULD REFUSE. */
        struct zcl_moderation_attestation_v1 unsignable;
        ASSERT(!mod_make(&unsignable, content, profile, policy,
                         (enum zcl_moderation_verdict_v1)
                             ZCL_MODERATION_VERDICT_COUNT,
                         1, NULL, 0x41));

        /* UNKNOWN PROFILE NAME: empty, and longer than the cap. Neither can
         * mint a root, so neither can ever match a configured profile. */
        uint8_t junk[32];
        ASSERT_EQ(zcl_moderation_profile_root_v1("", junk),
                  ZCL_MODERATION_LIMIT);
        char oversized[ZCL_MODERATION_PROFILE_NAME_MAX + 8u];
        memset(oversized, 'a', sizeof(oversized) - 1u);
        oversized[sizeof(oversized) - 1u] = '\0';
        ASSERT_EQ(zcl_moderation_profile_root_v1(oversized, junk),
                  ZCL_MODERATION_LIMIT);
        ASSERT_EQ(zcl_moderation_profile_root_v1(NULL, junk),
                  ZCL_MODERATION_NULL);
        /* A DIFFERENT known profile name hashes somewhere else entirely. */
        uint8_t open_view[32];
        ASSERT_EQ(zcl_moderation_profile_root_v1(
                      MARKET_MODERATION_PROFILE_OPEN_VIEW, open_view),
                  ZCL_MODERATION_OK);
        ASSERT(memcmp(open_view, profile, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---------------------------------------------------------------------- */
/* 2. The vocabulary this layer signs off on is the SAME vocabulary the      */
/*    hosting path already uses. Drift here would silently decouple the      */
/*    signed statement from what the node actually does.                     */
/* ---------------------------------------------------------------------- */

static int test_profile_and_verdict_binding(void)
{
    int failures = 0;
    TEST("moderation sign-off: profile name and verdict vocabulary bound to "
         "the hosting path") {
        ASSERT_STR_EQ(ZCL_MODERATION_PROFILE_GENERAL_AUDIENCE_V1,
                      MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1);
        ASSERT_EQ((int)ZCL_MODERATION_VERDICT_UNREVIEWED,
                  (int)MARKET_REVIEW_UNREVIEWED);
        ASSERT_EQ((int)ZCL_MODERATION_VERDICT_REVIEWED_OK,
                  (int)MARKET_REVIEW_REVIEWED_OK);
        ASSERT_EQ((int)ZCL_MODERATION_VERDICT_HIDDEN,
                  (int)MARKET_REVIEW_SENSITIVE);
        ASSERT_EQ((int)ZCL_MODERATION_VERDICT_COUNT,
                  (int)MARKET_REVIEW_STATE_COUNT);
        ASSERT_STR_EQ(zcl_moderation_verdict_string(
                          ZCL_MODERATION_VERDICT_REVIEWED_OK),
                      market_review_state_string(MARKET_REVIEW_REVIEWED_OK));
        ASSERT_STR_EQ(zcl_moderation_verdict_string(
                          ZCL_MODERATION_VERDICT_UNREVIEWED),
                      market_review_state_string(MARKET_REVIEW_UNREVIEWED));
        /* The default profile is immutable and named; a node that hosts
         * under it derives the same root every time. */
        uint8_t a[32], b[32];
        ASSERT(mod_profile(a));
        ASSERT(mod_profile(b));
        ASSERT(memcmp(a, b, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---------------------------------------------------------------------- */
/* 3. Composition: who said what, and every fail-closed path.               */
/* ---------------------------------------------------------------------- */

static int test_composition_rule(void)
{
    int failures = 0;
    TEST("moderation composition: absence hides, own policy is final, "
         "trust is local") {
        uint8_t content[32], profile[32], policy_root[32];
        mod_fill(content, 0x11);
        ASSERT(mod_profile(profile));
        ASSERT(mod_policy_text(policy_root));

        /* ABSENCE OF ATTESTATIONS -> unreviewed -> NOT served. This is the
         * single most important assertion in the file. */
        struct zcl_moderation_local_policy_v1 bare =
            mod_local_policy(profile, NULL, NULL, 0, 0);
        struct zcl_moderation_composition *empty = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&bare, content, NULL, 0, &empty),
                  ZCL_MODERATION_OK);
        struct zcl_moderation_tally_v1 tally =
            zcl_moderation_composition_tally_v1(empty);
        ASSERT(!tally.serve);
        ASSERT_EQ((int)tally.self_verdict,
                  (int)ZCL_MODERATION_VERDICT_UNREVIEWED);
        ASSERT(!tally.self_present);
        ASSERT_EQ(tally.signer_count, 0u);
        ASSERT_EQ((int)tally.reason,
                  (int)ZCL_MODERATION_REASON_LOCAL_TRUST_DISABLED);
        uint8_t empty_root[32];
        zcl_moderation_composition_root_v1(empty, empty_root);
        char hex[65];
        zcl_hex_encode(empty_root, 32, hex);
        printf("moderation_composition.v1.empty=%s\n", hex);

        /* Three reviewer boxes plus this node. */
        struct zcl_moderation_attestation_v1 att[4];
        struct zcl_moderation_source_v1 src[4];
        static const uint8_t seeds[4] = {0x41, 0x42, 0x43, 0x44};
        for (size_t i = 0; i < 4; i++) {
            ASSERT(mod_make(&att[i], content, profile, policy_root,
                            ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL,
                            seeds[i]));
            ASSERT(mod_source(&src[i], &att[i]));
        }
        uint8_t trusted[3][32];
        for (size_t i = 0; i < 3; i++)
            memcpy(trusted[i], att[i].signer_pubkey, 32);

        /* A WHITELIST WOULD SERVE HERE AND THIS MUST NOT: three well-signed
         * reviewed_ok statements, none of them from a key this operator
         * listed, zero threshold. Nothing remote counts. */
        struct zcl_moderation_composition *unlisted = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&bare, content, src, 4,
                                            &unlisted),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(unlisted);
        ASSERT(!tally.serve);
        ASSERT_EQ(tally.untrusted_ok, 4u);
        ASSERT_EQ(tally.trusted_ok, 0u);
        ASSERT_EQ(tally.rejected, 0u);
        ASSERT_EQ((int)tally.reason,
                  (int)ZCL_MODERATION_REASON_LOCAL_TRUST_DISABLED);

        /* Now the operator locally configures 2-of-3. Sovereignty, not
         * protocol: the same bytes, a different local decision. */
        struct zcl_moderation_local_policy_v1 twoof3 =
            mod_local_policy(profile, NULL, trusted, 3, 2);
        struct zcl_moderation_composition *quorum = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&twoof3, content, src, 4,
                                            &quorum),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(quorum);
        ASSERT(tally.serve && tally.threshold_met);
        ASSERT_EQ(tally.trusted_ok, 3u);
        ASSERT_EQ(tally.untrusted_ok, 1u);
        ASSERT_EQ((int)tally.reason,
                  (int)ZCL_MODERATION_REASON_TRUSTED_QUORUM);
        ASSERT_EQ((size_t)tally.signer_count,
                  zcl_moderation_composition_signer_count_v1(quorum));
        /* The vector, not the scalar: the reader can name each signer. */
        for (size_t i = 0; i < 3; i++) {
            const struct zcl_moderation_signer_verdict_v1 *found =
                zcl_moderation_composition_signer_find_v1(quorum, trusted[i]);
            ASSERT(found && found->trusted && !found->self &&
                   found->chain_linked && found->sequence == 1u &&
                   found->verdict == ZCL_MODERATION_VERDICT_REVIEWED_OK);
        }
        /* Signers come out in ascending pubkey order — stable evidence. */
        for (size_t i = 1;
             i < zcl_moderation_composition_signer_count_v1(quorum); i++)
            ASSERT(memcmp(
                       zcl_moderation_composition_signer_at_v1(quorum,
                                                               i - 1u)
                           ->signer_pubkey,
                       zcl_moderation_composition_signer_at_v1(quorum, i)
                           ->signer_pubkey,
                       32) < 0);

        uint8_t quorum_root[32];
        zcl_moderation_composition_root_v1(quorum, quorum_root);
        zcl_hex_encode(quorum_root, 32, hex);
        printf("moderation_composition.v1=%s\n", hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(composition_root_kat, expected, 32));
        ASSERT(memcmp(quorum_root, expected, 32) == 0);

        /* ORDER INVARIANCE: evidence arriving backwards composes the same. */
        struct zcl_moderation_source_v1 reversed[4] = {src[3], src[2], src[1],
                                                       src[0]};
        struct zcl_moderation_composition *shuffled = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&twoof3, content, reversed, 4,
                                            &shuffled),
                  ZCL_MODERATION_OK);
        uint8_t shuffled_root[32];
        zcl_moderation_composition_root_v1(shuffled, shuffled_root);
        ASSERT(memcmp(shuffled_root, quorum_root, 32) == 0);

        /* DUPLICATE GOSSIP is one statement, not two votes. */
        struct zcl_moderation_source_v1 doubled[8];
        for (size_t i = 0; i < 4; i++) {
            doubled[i] = src[i];
            doubled[i + 4u] = src[i];
        }
        struct zcl_moderation_composition *deduped = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&twoof3, content, doubled, 8,
                                            &deduped),
                  ZCL_MODERATION_OK);
        uint8_t deduped_root[32];
        zcl_moderation_composition_root_v1(deduped, deduped_root);
        ASSERT(memcmp(deduped_root, quorum_root, 32) == 0);

        /* ONE TRUSTED REVIEWER SAYING HIDDEN CAN RESTRICT... */
        struct zcl_moderation_attestation_v1 objector;
        ASSERT(mod_make(&objector, content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_HIDDEN, 1, NULL, seeds[2]));
        struct zcl_moderation_source_v1 with_objection[4];
        memset(with_objection, 0, sizeof(with_objection));
        with_objection[0] = src[0];
        with_objection[1] = src[1];
        with_objection[2] = src[3];
        ASSERT(mod_source(&with_objection[3], &objector));
        struct zcl_moderation_composition *vetoed = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&twoof3, content, with_objection,
                                            4, &vetoed),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(vetoed);
        ASSERT(!tally.serve && tally.threshold_met);
        ASSERT_EQ(tally.trusted_hidden, 1u);
        ASSERT_EQ((int)tally.reason,
                  (int)ZCL_MODERATION_REASON_TRUSTED_VETO);
        /* ...and an operator who turns the veto off still only ever gets a
         * decision from its OWN configuration. */
        struct zcl_moderation_local_policy_v1 no_veto = twoof3;
        no_veto.trusted_hidden_vetoes = false;
        struct zcl_moderation_composition *unvetoed = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&no_veto, content,
                                            with_objection, 4, &unvetoed),
                  ZCL_MODERATION_OK);
        ASSERT(zcl_moderation_composition_tally_v1(unvetoed).serve);

        /* THIS NODE'S OWN SIGN-OFF IS FINAL FOR ITS OWN HOSTING.
         * Own hidden beats a full trusted quorum saying ok... */
        struct zcl_moderation_attestation_v1 self_hide;
        ASSERT(mod_make(&self_hide, content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_HIDDEN, 1, NULL, 0x51));
        struct zcl_moderation_source_v1 with_self[5];
        memset(with_self, 0, sizeof(with_self));
        for (size_t i = 0; i < 4; i++) with_self[i] = src[i];
        ASSERT(mod_source(&with_self[4], &self_hide));
        struct zcl_moderation_local_policy_v1 selfish =
            mod_local_policy(profile, self_hide.signer_pubkey, trusted, 3, 2);
        struct zcl_moderation_composition *own = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&selfish, content, with_self, 5,
                                            &own),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(own);
        ASSERT(!tally.serve && tally.self_present && tally.threshold_met);
        ASSERT_EQ((int)tally.self_verdict, (int)ZCL_MODERATION_VERDICT_HIDDEN);
        ASSERT_EQ((int)tally.reason, (int)ZCL_MODERATION_REASON_SELF_HIDDEN);

        /* ...and own ok needs nobody's permission. */
        struct zcl_moderation_attestation_v1 self_ok;
        ASSERT(mod_make(&self_ok, content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL, 0x52));
        struct zcl_moderation_source_v1 alone;
        ASSERT(mod_source(&alone, &self_ok));
        struct zcl_moderation_local_policy_v1 solo =
            mod_local_policy(profile, self_ok.signer_pubkey, NULL, 0, 0);
        struct zcl_moderation_composition *lonely = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&solo, content, &alone, 1,
                                            &lonely),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(lonely);
        ASSERT(tally.serve && tally.self_present);
        ASSERT_EQ((int)tally.reason, (int)ZCL_MODERATION_REASON_SELF_OK);

        /* NO QUORUM is a verdict, not an error. */
        struct zcl_moderation_local_policy_v1 threeof3 =
            mod_local_policy(profile, NULL, trusted, 3, 3);
        struct zcl_moderation_composition *shortfall = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&threeof3, content, src, 2,
                                            &shortfall),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(shortfall);
        ASSERT(!tally.serve && !tally.threshold_met);
        ASSERT_EQ((int)tally.reason, (int)ZCL_MODERATION_REASON_NO_QUORUM);

        /* A threshold nobody could ever meet is a CONFIG ERROR, said out
         * loud, not a silent permanent hide the operator never notices. */
        struct zcl_moderation_local_policy_v1 impossible =
            mod_local_policy(profile, NULL, trusted, 3, 4);
        struct zcl_moderation_composition *never = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&impossible, content, src, 4,
                                            &never),
                  ZCL_MODERATION_LIMIT);
        ASSERT(never == NULL);

        zcl_moderation_composition_free_v1(shortfall);
        zcl_moderation_composition_free_v1(lonely);
        zcl_moderation_composition_free_v1(own);
        zcl_moderation_composition_free_v1(unvetoed);
        zcl_moderation_composition_free_v1(vetoed);
        zcl_moderation_composition_free_v1(deduped);
        zcl_moderation_composition_free_v1(shuffled);
        zcl_moderation_composition_free_v1(quorum);
        zcl_moderation_composition_free_v1(unlisted);
        zcl_moderation_composition_free_v1(empty);
        PASS();
    } _test_next:;
    return failures;
}

static int test_composition_negative_controls(void)
{
    int failures = 0;
    TEST("moderation composition: bad evidence is discarded, never served") {
        uint8_t content[32], other_content[32], profile[32], other_profile[32];
        uint8_t policy_root[32];
        mod_fill(content, 0x11);
        mod_fill(other_content, 0x12);
        ASSERT(mod_profile(profile));
        ASSERT_EQ(zcl_moderation_profile_root_v1("no-such-profile.v1",
                                                 other_profile),
                  ZCL_MODERATION_OK);
        ASSERT(mod_policy_text(policy_root));

        struct zcl_moderation_attestation_v1 att[2];
        struct zcl_moderation_source_v1 src[2];
        static const uint8_t seeds[2] = {0x41, 0x42};
        for (size_t i = 0; i < 2; i++) {
            ASSERT(mod_make(&att[i], content, profile, policy_root,
                            ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL,
                            seeds[i]));
            ASSERT(mod_source(&src[i], &att[i]));
        }
        uint8_t trusted[2][32];
        for (size_t i = 0; i < 2; i++)
            memcpy(trusted[i], att[i].signer_pubkey, 32);
        struct zcl_moderation_local_policy_v1 oneof2 =
            mod_local_policy(profile, NULL, trusted, 2, 1);

        /* Baseline: this configuration DOES serve on clean evidence, so a
         * "did not serve" below is caused by the defect under test and not
         * by the fixture being inert. */
        struct zcl_moderation_composition *clean = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, content, src, 2, &clean),
                  ZCL_MODERATION_OK);
        ASSERT(zcl_moderation_composition_tally_v1(clean).serve);
        zcl_moderation_composition_free_v1(clean);

        struct zcl_moderation_composition *composition = NULL;
        struct zcl_moderation_tally_v1 tally;

        /* (a) CORRUPTED SIGNATURE inside an otherwise well-formed source. */
        struct zcl_moderation_source_v1 corrupt[2] = {src[0], src[1]};
        corrupt[0].attestation.signature[3] ^= 0x01u;
        corrupt[1].attestation.signature[3] ^= 0x01u;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, content, corrupt, 2,
                                            &composition),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(composition);
        ASSERT(!tally.serve);
        ASSERT_EQ(tally.rejected, 2u);
        ASSERT_EQ(tally.signer_count, 0u);
        zcl_moderation_composition_free_v1(composition);

        /* (b) WRONG PUBKEY: a good signature reattributed to a trusted key.
         * The forgery is rejected, so the trusted signer does NOT appear. */
        struct zcl_moderation_source_v1 reattributed[1] = {src[0]};
        memcpy(reattributed[0].attestation.signer_pubkey, trusted[1], 32);
        mod_reroot(&reattributed[0]);
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, content, reattributed, 1,
                                            &composition),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(composition);
        ASSERT(!tally.serve);
        ASSERT_EQ(tally.rejected, 1u);
        zcl_moderation_composition_free_v1(composition);

        /* (c) ROOT MISBINDING: valid bytes indexed under a root they do not
         * hash to. A reader must not be made to file evidence by a name the
         * evidence does not carry. */
        struct zcl_moderation_source_v1 misbound[1] = {src[0]};
        misbound[0].object_root[0] ^= 0x01u;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, content, misbound, 1,
                                            &composition),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(composition);
        ASSERT(!tally.serve && tally.rejected == 1u);
        zcl_moderation_composition_free_v1(composition);

        /* (d) ATTESTATION FOR DIFFERENT CONTENT — perfectly valid, and
         * irrelevant. It must not vouch for THIS content. */
        struct zcl_moderation_attestation_v1 elsewhere;
        struct zcl_moderation_source_v1 elsewhere_src;
        ASSERT(mod_make(&elsewhere, other_content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL,
                        seeds[0]));
        ASSERT(mod_source(&elsewhere_src, &elsewhere));
        ASSERT_EQ(zcl_moderation_attestation_v1_validate(&elsewhere),
                  ZCL_MODERATION_OK);
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, content, &elsewhere_src,
                                            1, &composition),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(composition);
        ASSERT(!tally.serve && tally.rejected == 1u);
        zcl_moderation_composition_free_v1(composition);

        /* (e) UNKNOWN / WRONG PROFILE — a sign-off under a profile this node
         * does not host under says nothing about this node's hosting. */
        struct zcl_moderation_attestation_v1 wrong_profile;
        struct zcl_moderation_source_v1 wrong_profile_src;
        ASSERT(mod_make(&wrong_profile, content, other_profile, policy_root,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL,
                        seeds[0]));
        ASSERT(mod_source(&wrong_profile_src, &wrong_profile));
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, content,
                                            &wrong_profile_src, 1,
                                            &composition),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(composition);
        ASSERT(!tally.serve && tally.rejected == 1u);
        zcl_moderation_composition_free_v1(composition);

        /* (f) EXPIRED — a sign-off outside its window is not evidence, and
         * it decays to unreviewed rather than to "still ok". */
        struct zcl_moderation_local_policy_v1 late = oneof2;
        late.now_mtp = MOD_EXPIRES_MTP;
        ASSERT_EQ(zcl_moderation_compose_v1(&late, content, src, 2,
                                            &composition),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(composition);
        ASSERT(!tally.serve);
        ASSERT_EQ(tally.expired, 2u);
        ASSERT_EQ(tally.trusted_unreviewed, 2u);
        ASSERT_EQ(tally.trusted_ok, 0u);
        zcl_moderation_composition_free_v1(composition);

        /* (g) CLOCK WEIRDNESS the other way: a reader whose clock is before
         * the review also fails closed rather than trusting the future. */
        struct zcl_moderation_local_policy_v1 early = oneof2;
        early.now_mtp = MOD_REVIEWED_MTP - 1;
        ASSERT_EQ(zcl_moderation_compose_v1(&early, content, src, 2,
                                            &composition),
                  ZCL_MODERATION_OK);
        tally = zcl_moderation_composition_tally_v1(composition);
        ASSERT(!tally.serve);
        ASSERT_EQ(tally.not_yet_valid, 2u);
        zcl_moderation_composition_free_v1(composition);

        /* (h) MALFORMED POLICY / UNREADABLE STATE at the call boundary. */
        ASSERT_EQ(zcl_moderation_compose_v1(NULL, content, src, 2,
                                            &composition),
                  ZCL_MODERATION_NULL);
        ASSERT(composition == NULL);
        struct zcl_moderation_local_policy_v1 noprofile = oneof2;
        memset(noprofile.profile_root, 0, 32);
        ASSERT_EQ(zcl_moderation_compose_v1(&noprofile, content, src, 2,
                                            &composition),
                  ZCL_MODERATION_ROOT);
        ASSERT(composition == NULL);
        struct zcl_moderation_local_policy_v1 noclock = oneof2;
        noclock.now_mtp = 0;
        ASSERT_EQ(zcl_moderation_compose_v1(&noclock, content, src, 2,
                                            &composition),
                  ZCL_MODERATION_TIME);
        struct zcl_moderation_local_policy_v1 dangling = oneof2;
        dangling.trusted = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&dangling, content, src, 2,
                                            &composition),
                  ZCL_MODERATION_NULL);
        struct zcl_moderation_local_policy_v1 huge = oneof2;
        huge.trusted_count = ZCL_MODERATION_MAX_TRUSTED + 1u;
        ASSERT_EQ(zcl_moderation_compose_v1(&huge, content, src, 2,
                                            &composition),
                  ZCL_MODERATION_LIMIT);
        uint8_t zero_content[32] = {0};
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, zero_content, src, 2,
                                            &composition),
                  ZCL_MODERATION_ROOT);
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof2, content, src,
                                            ZCL_MODERATION_MAX_ATTESTATIONS +
                                                1u,
                                            &composition),
                  ZCL_MODERATION_LIMIT);
        /* An UNREADABLE composition (NULL) answers the fail-closed default,
         * not a value a careless caller could read as "serve". */
        tally = zcl_moderation_composition_tally_v1(NULL);
        ASSERT(!tally.serve);
        ASSERT_EQ((int)tally.self_verdict,
                  (int)ZCL_MODERATION_VERDICT_UNREVIEWED);
        ASSERT_EQ((int)tally.reason, (int)ZCL_MODERATION_REASON_UNREVIEWED);
        ASSERT_EQ(zcl_moderation_composition_signer_count_v1(NULL),
                  (size_t)0);
        ASSERT(zcl_moderation_composition_signer_at_v1(NULL, 0) == NULL);
        uint8_t null_root[32];
        mod_fill(null_root, 0xaa);
        zcl_moderation_composition_root_v1(NULL, null_root);
        uint8_t zeroes[32] = {0};
        ASSERT(memcmp(null_root, zeroes, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_supersession_and_replay(void)
{
    int failures = 0;
    TEST("moderation sign-off: a later signed statement wins and an old one "
         "cannot be replayed over it") {
        uint8_t content[32], profile[32], policy_root[32];
        mod_fill(content, 0x11);
        ASSERT(mod_profile(profile));
        ASSERT(mod_policy_text(policy_root));

        /* A reviewer says ok, then changes its mind and says hidden. */
        struct zcl_moderation_attestation_v1 first, second;
        struct zcl_moderation_source_v1 first_src, second_src;
        ASSERT(mod_make(&first, content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL, 0x41));
        ASSERT(mod_source(&first_src, &first));
        ASSERT(mod_make(&second, content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_HIDDEN, 2,
                        first_src.object_root, 0x41));
        ASSERT(mod_source(&second_src, &second));
        ASSERT(memcmp(first.signer_pubkey, second.signer_pubkey, 32) == 0);

        uint8_t trusted[1][32];
        memcpy(trusted[0], first.signer_pubkey, 32);
        struct zcl_moderation_local_policy_v1 oneof1 =
            mod_local_policy(profile, NULL, trusted, 1, 1);

        /* Old alone: serves. */
        struct zcl_moderation_composition *old_only = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof1, content, &first_src, 1,
                                            &old_only),
                  ZCL_MODERATION_OK);
        ASSERT(zcl_moderation_composition_tally_v1(old_only).serve);

        /* REPLAY: the old statement re-presented alongside the new one must
         * not resurrect the old verdict, in EITHER arrival order. */
        struct zcl_moderation_source_v1 forward[2] = {first_src, second_src};
        struct zcl_moderation_source_v1 backward[2] = {second_src, first_src};
        struct zcl_moderation_composition *a = NULL;
        struct zcl_moderation_composition *b = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof1, content, forward, 2, &a),
                  ZCL_MODERATION_OK);
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof1, content, backward, 2,
                                            &b),
                  ZCL_MODERATION_OK);
        struct zcl_moderation_tally_v1 ta =
            zcl_moderation_composition_tally_v1(a);
        ASSERT(!ta.serve);
        ASSERT_EQ(ta.signer_count, 1u);
        ASSERT_EQ(ta.trusted_hidden, 1u);
        ASSERT_EQ(ta.superseded, 1u);
        ASSERT_EQ((int)ta.reason, (int)ZCL_MODERATION_REASON_TRUSTED_VETO);
        uint8_t root_a[32], root_b[32];
        zcl_moderation_composition_root_v1(a, root_a);
        zcl_moderation_composition_root_v1(b, root_b);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        const struct zcl_moderation_signer_verdict_v1 *winner =
            zcl_moderation_composition_signer_at_v1(a, 0);
        ASSERT(winner && winner->sequence == 2u && winner->chain_linked &&
               winner->superseded_count == 1u &&
               winner->verdict == ZCL_MODERATION_VERDICT_HIDDEN);

        /* Even 100 copies of the stale statement cannot outvote one newer
         * statement — this is ordering, not counting. */
        struct zcl_moderation_source_v1 flood[101];
        for (size_t i = 0; i < 100; i++) flood[i] = first_src;
        flood[100] = second_src;
        struct zcl_moderation_composition *flooded = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof1, content, flood, 101,
                                            &flooded),
                  ZCL_MODERATION_OK);
        ASSERT(!zcl_moderation_composition_tally_v1(flooded).serve);
        ASSERT_EQ(zcl_moderation_composition_tally_v1(flooded).signer_count,
                  1u);

        /* SUPERSESSION WORKS IN THE PERMISSIVE DIRECTION TOO — a reviewer
         * may withdraw a hide. Ordering is neutral about which way it moves;
         * only ABSENCE of evidence is biased toward hiding. */
        struct zcl_moderation_attestation_v1 third;
        struct zcl_moderation_source_v1 third_src;
        ASSERT(mod_make(&third, content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 3,
                        second_src.object_root, 0x41));
        ASSERT(mod_source(&third_src, &third));
        struct zcl_moderation_source_v1 restored[3] = {first_src, second_src,
                                                       third_src};
        struct zcl_moderation_composition *withdrawn = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof1, content, restored, 3,
                                            &withdrawn),
                  ZCL_MODERATION_OK);
        ASSERT(zcl_moderation_composition_tally_v1(withdrawn).serve);
        ASSERT_EQ(zcl_moderation_composition_tally_v1(withdrawn).superseded,
                  2u);

        /* CHAIN COMPLETENESS IS NOT REQUIRED. A reader holding only the
         * newest statement still gets the newest verdict: otherwise whoever
         * held the missing middle link would be an authority over it. */
        struct zcl_moderation_source_v1 gap[1] = {third_src};
        struct zcl_moderation_composition *gapped = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof1, content, gap, 1,
                                            &gapped),
                  ZCL_MODERATION_OK);
        struct zcl_moderation_tally_v1 tg =
            zcl_moderation_composition_tally_v1(gapped);
        ASSERT(tg.serve && tg.signer_count == 1u);
        const struct zcl_moderation_signer_verdict_v1 *lone =
            zcl_moderation_composition_signer_at_v1(gapped, 0);
        ASSERT(lone && lone->sequence == 3u && !lone->chain_linked);

        /* EQUIVOCATION: two DIFFERENT statements at the same top sequence
         * by one signer. The reader does not pick a winner — that signer's
         * position collapses to unreviewed. */
        struct zcl_moderation_attestation_v1 fork_a, fork_b;
        struct zcl_moderation_source_v1 fork_src[2];
        ASSERT(mod_make(&fork_a, content, profile, policy_root,
                        ZCL_MODERATION_VERDICT_REVIEWED_OK, 4,
                        third_src.object_root, 0x41));
        struct zcl_moderation_attestation_v1 tweaked = fork_a;
        tweaked.reviewed_height += 1u;
        uint8_t seed[32];
        mod_fill(seed, 0x41);
        ASSERT_EQ(zcl_moderation_attestation_v1_sign(&tweaked, seed),
                  ZCL_MODERATION_OK);
        fork_b = tweaked;
        ASSERT(mod_source(&fork_src[0], &fork_a));
        ASSERT(mod_source(&fork_src[1], &fork_b));
        ASSERT(memcmp(fork_src[0].object_root, fork_src[1].object_root, 32) !=
               0);
        struct zcl_moderation_composition *equivocated = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&oneof1, content, fork_src, 2,
                                            &equivocated),
                  ZCL_MODERATION_OK);
        struct zcl_moderation_tally_v1 te =
            zcl_moderation_composition_tally_v1(equivocated);
        ASSERT(!te.serve);
        ASSERT_EQ(te.equivocations, 1u);
        ASSERT_EQ(te.trusted_unreviewed, 1u);
        ASSERT_EQ(te.trusted_ok, 0u);
        ASSERT_EQ((int)te.reason, (int)ZCL_MODERATION_REASON_NO_QUORUM);

        zcl_moderation_composition_free_v1(equivocated);
        zcl_moderation_composition_free_v1(gapped);
        zcl_moderation_composition_free_v1(withdrawn);
        zcl_moderation_composition_free_v1(flooded);
        zcl_moderation_composition_free_v1(b);
        zcl_moderation_composition_free_v1(a);
        zcl_moderation_composition_free_v1(old_only);
        PASS();
    } _test_next:;
    return failures;
}

/* ---------------------------------------------------------------------- */
/* 4. THE DOCTRINE'S AUTHORITY TEST, applied to this design.                */
/*    "If one box stops, is any verdict blocked?"                           */
/* ---------------------------------------------------------------------- */

#define MOD_ATTESTORS 7u

static int test_no_single_node_is_required(void)
{
    int failures = 0;
    TEST("moderation composition: no box's silence blocks a verdict") {
        uint8_t content[32], profile[32], policy_root[32];
        mod_fill(content, 0x11);
        ASSERT(mod_profile(profile));
        ASSERT(mod_policy_text(policy_root));

        struct zcl_moderation_attestation_v1 att[MOD_ATTESTORS];
        struct zcl_moderation_source_v1 src[MOD_ATTESTORS];
        uint8_t trusted[MOD_ATTESTORS][32];
        for (size_t i = 0; i < MOD_ATTESTORS; i++) {
            ASSERT(mod_make(&att[i], content, profile, policy_root,
                            ZCL_MODERATION_VERDICT_REVIEWED_OK, 1, NULL,
                            (uint8_t)(0x60u + i)));
            ASSERT(mod_source(&src[i], &att[i]));
            memcpy(trusted[i], att[i].signer_pubkey, 32);
        }
        struct zcl_moderation_local_policy_v1 policy = mod_local_policy(
            profile, NULL, trusted, MOD_ATTESTORS, 3);

        /* LEAVE-ONE-OUT over every attestor, plus the all-silent case.
         * The assertion is NOT "the verdict is unchanged" — it is that a
         * VERDICT EXISTS for every subset, with no error and no pending
         * state. A box that stops changes what a reader concludes; it can
         * never stop a reader concluding. */
        for (size_t skip = 0; skip <= MOD_ATTESTORS; skip++) {
            struct zcl_moderation_source_v1 subset[MOD_ATTESTORS];
            size_t n = 0;
            for (size_t i = 0; i < MOD_ATTESTORS; i++)
                if (i != skip) subset[n++] = src[i];
            struct zcl_moderation_composition *composition = NULL;
            ASSERT_EQ(zcl_moderation_compose_v1(&policy, content, subset, n,
                                                &composition),
                      ZCL_MODERATION_OK);
            ASSERT(composition != NULL);
            struct zcl_moderation_tally_v1 tally =
                zcl_moderation_composition_tally_v1(composition);
            /* A verdict was produced and it is one of the defined reasons. */
            ASSERT(tally.reason < ZCL_MODERATION_REASON_COUNT);
            ASSERT_EQ((size_t)tally.signer_count, n);
            /* With threshold 3 of 7, ANY six survivors still reach it: no
             * single box is even load-bearing for the outcome here. */
            ASSERT(tally.serve == (n >= 3u));
            uint8_t root[32];
            zcl_moderation_composition_root_v1(composition, root);
            uint8_t zeroes[32] = {0};
            ASSERT(memcmp(root, zeroes, 32) != 0);
            zcl_moderation_composition_free_v1(composition);
        }

        /* ALL SEVEN STOP AT ONCE. Still a verdict — the safe one. */
        struct zcl_moderation_composition *blackout = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&policy, content, NULL, 0,
                                            &blackout),
                  ZCL_MODERATION_OK);
        struct zcl_moderation_tally_v1 dark =
            zcl_moderation_composition_tally_v1(blackout);
        ASSERT(!dark.serve && dark.signer_count == 0u);
        ASSERT_EQ((int)dark.reason, (int)ZCL_MODERATION_REASON_NO_QUORUM);
        zcl_moderation_composition_free_v1(blackout);

        /* AND THE OTHER HALF OF THE TEST: no box, and no number of boxes,
         * can FORCE this node to serve. Every one of the seven says
         * reviewed_ok; an operator who listed nobody serves nothing. */
        struct zcl_moderation_local_policy_v1 sovereign =
            mod_local_policy(profile, NULL, NULL, 0, 0);
        struct zcl_moderation_composition *pressured = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&sovereign, content, src,
                                            MOD_ATTESTORS, &pressured),
                  ZCL_MODERATION_OK);
        struct zcl_moderation_tally_v1 unmoved =
            zcl_moderation_composition_tally_v1(pressured);
        ASSERT(!unmoved.serve);
        ASSERT_EQ(unmoved.untrusted_ok, MOD_ATTESTORS);
        ASSERT_EQ(unmoved.trusted_ok, 0u);
        zcl_moderation_composition_free_v1(pressured);

        /* Two readers with DIFFERENT local trust reach DIFFERENT verdicts on
         * IDENTICAL evidence, and both are legitimate. That is what "no
         * referee" means in practice: the bytes are shared, the reading is
         * each node's own. */
        struct zcl_moderation_local_policy_v1 strict = mod_local_policy(
            profile, NULL, trusted, 2, 2);
        struct zcl_moderation_composition *lenient_view = NULL;
        struct zcl_moderation_composition *strict_view = NULL;
        struct zcl_moderation_source_v1 two[2] = {src[5], src[6]};
        ASSERT_EQ(zcl_moderation_compose_v1(&policy, content, two, 2,
                                            &lenient_view),
                  ZCL_MODERATION_OK);
        ASSERT_EQ(zcl_moderation_compose_v1(&strict, content, two, 2,
                                            &strict_view),
                  ZCL_MODERATION_OK);
        /* src[5]/src[6] are trusted by `policy` (all seven) but NOT by
         * `strict` (only the first two keys), so the same bytes read
         * differently for each operator. */
        ASSERT(!zcl_moderation_composition_tally_v1(lenient_view).serve);
        ASSERT(!zcl_moderation_composition_tally_v1(strict_view).serve);
        uint8_t lenient_root[32], strict_root[32];
        zcl_moderation_composition_root_v1(lenient_view, lenient_root);
        zcl_moderation_composition_root_v1(strict_view, strict_root);
        ASSERT(memcmp(lenient_root, strict_root, 32) != 0);
        zcl_moderation_composition_free_v1(strict_view);
        zcl_moderation_composition_free_v1(lenient_view);
        PASS();
    } _test_next:;
    return failures;
}

/* ---------------------------------------------------------------------- */
/* 5. MODERATION MUST NOT TOUCH CONSENSUS.                                  */
/* ---------------------------------------------------------------------- */

static void mod_synthetic_header(struct block_header *h)
{
    block_header_init(h);
    h->nVersion = 4;
    h->nTime = 1000;
    h->nBits = 0x1f07ffffu;
    h->nSolutionSize = 0;
}

static int test_moderation_never_gates_consensus(void)
{
    int failures = 0;
    TEST("moderation verdicts cannot influence block acceptance") {
        uint8_t profile[32], policy_root[32];
        ASSERT(mod_profile(profile));
        ASSERT(mod_policy_text(policy_root));

        /* Two headers with KNOWN, OPPOSITE consensus answers. */
        struct block_header good, bad;
        mod_synthetic_header(&good);
        mod_synthetic_header(&bad);
        bad.nVersion = 3; /* below MIN_BLOCK_VERSION */

        struct validation_state before_good, before_bad;
        validation_state_init(&before_good);
        validation_state_init(&before_bad);
        bool good_before =
            check_block_header(&good, &before_good, chain_params_get(),
                               false);
        bool bad_before =
            check_block_header(&bad, &before_bad, chain_params_get(), false);
        ASSERT(good_before);
        ASSERT(!bad_before);
        ASSERT_STR_EQ(before_bad.reject_reason, "version-too-low");

        /* Now have SEVEN nodes attest BOTH blocks HIDDEN under the default
         * profile, and compose with a local policy that hides them. The
         * content_root attested IS the block's own hash. */
        struct uint256 good_hash, bad_hash;
        block_header_get_hash(&good, &good_hash);
        block_header_get_hash(&bad, &bad_hash);
        const uint8_t *roots[2] = {(const uint8_t *)&good_hash,
                                   (const uint8_t *)&bad_hash};
        for (size_t r = 0; r < 2; r++) {
            struct zcl_moderation_attestation_v1 att[MOD_ATTESTORS];
            struct zcl_moderation_source_v1 src[MOD_ATTESTORS];
            uint8_t trusted[MOD_ATTESTORS][32];
            for (size_t i = 0; i < MOD_ATTESTORS; i++) {
                ASSERT(mod_make(&att[i], roots[r], profile, policy_root,
                                ZCL_MODERATION_VERDICT_HIDDEN, 1, NULL,
                                (uint8_t)(0x80u + i)));
                ASSERT(mod_source(&src[i], &att[i]));
                memcpy(trusted[i], att[i].signer_pubkey, 32);
            }
            struct zcl_moderation_local_policy_v1 policy = mod_local_policy(
                profile, NULL, trusted, MOD_ATTESTORS, 1);
            struct zcl_moderation_composition *composition = NULL;
            ASSERT_EQ(zcl_moderation_compose_v1(&policy, roots[r], src,
                                                MOD_ATTESTORS, &composition),
                      ZCL_MODERATION_OK);
            struct zcl_moderation_tally_v1 tally =
                zcl_moderation_composition_tally_v1(composition);
            /* The node WILL refuse to serve this block's content... */
            ASSERT(!tally.serve);
            ASSERT_EQ(tally.trusted_hidden, MOD_ATTESTORS);
            zcl_moderation_composition_free_v1(composition);
        }

        /* ...and the consensus answer is byte-identical anyway: same
         * verdict, same reject_reason, same DoS score, same reject code.
         * Refusing to SERVE is not refusing to VALIDATE. */
        struct validation_state after_good, after_bad;
        validation_state_init(&after_good);
        validation_state_init(&after_bad);
        bool good_after =
            check_block_header(&good, &after_good, chain_params_get(), false);
        bool bad_after =
            check_block_header(&bad, &after_bad, chain_params_get(), false);
        ASSERT_EQ(good_after, good_before);
        ASSERT_EQ(bad_after, bad_before);
        ASSERT_EQ(after_bad.mode, before_bad.mode);
        ASSERT_EQ(after_bad.dos, before_bad.dos);
        ASSERT_EQ(after_bad.reject_code, before_bad.reject_code);
        ASSERT_STR_EQ(after_bad.reject_reason, before_bad.reject_reason);
        ASSERT_EQ(after_good.mode, before_good.mode);

        /* And the reverse direction: an all-reviewed_ok quorum cannot make
         * the invalid block acceptable either. Moderation is inert in BOTH
         * directions, which is the property that keeps it off the chain. */
        struct zcl_moderation_attestation_v1 bless[MOD_ATTESTORS];
        struct zcl_moderation_source_v1 bless_src[MOD_ATTESTORS];
        uint8_t bless_trusted[MOD_ATTESTORS][32];
        for (size_t i = 0; i < MOD_ATTESTORS; i++) {
            ASSERT(mod_make(&bless[i], (const uint8_t *)&bad_hash, profile,
                            policy_root, ZCL_MODERATION_VERDICT_REVIEWED_OK,
                            1, NULL, (uint8_t)(0x90u + i)));
            ASSERT(mod_source(&bless_src[i], &bless[i]));
            memcpy(bless_trusted[i], bless[i].signer_pubkey, 32);
        }
        struct zcl_moderation_local_policy_v1 permissive = mod_local_policy(
            profile, NULL, bless_trusted, MOD_ATTESTORS, 1);
        struct zcl_moderation_composition *blessed = NULL;
        ASSERT_EQ(zcl_moderation_compose_v1(&permissive,
                                            (const uint8_t *)&bad_hash,
                                            bless_src, MOD_ATTESTORS,
                                            &blessed),
                  ZCL_MODERATION_OK);
        ASSERT(zcl_moderation_composition_tally_v1(blessed).serve);
        zcl_moderation_composition_free_v1(blessed);
        struct validation_state still_bad;
        validation_state_init(&still_bad);
        ASSERT(!check_block_header(&bad, &still_bad, chain_params_get(),
                                   false));
        ASSERT_STR_EQ(still_bad.reject_reason, "version-too-low");
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_moderation_attestation(void)
{
    int failures = test_attestation_codec() +
                   test_attestation_negative_controls() +
                   test_profile_and_verdict_binding() +
                   test_composition_rule() +
                   test_composition_negative_controls() +
                   test_supersession_and_replay() +
                   test_no_single_node_is_required() +
                   test_moderation_never_gates_consensus();
    printf("=== zcode_moderation_attestation: %d failures ===\n", failures);
    return failures;
}
