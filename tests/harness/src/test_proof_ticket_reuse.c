/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: False-hit regressions and a deterministic reuse measurement for
 *          component proof keys and signed proof tickets (vcs/proof_ticket.h).
 *
 * Every case here guards one way a reused proof could claim work it never
 * covered: one changed byte in any of the fifteen key fields, a forged or
 * candidate-domain signature, the same-uid local proof signer, a copied
 * (unreproduced) observation, a contradiction, a ticket whose key is not
 * its preimage, malformed wire, a policy change and a one-signer quorum.
 * The measurement simulates candidates over a 200-unit tree with three
 * independent verifier identities and asserts zero false hits. */

#include "test/test_core.h"

#include "vcs/package_store.h"
#include "vcs/proof_ticket.h"

#include "crypto/ed25519.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PTT_A = 0, PTT_B, PTT_C, PTT_AUTHOR, PTT_LOCAL, PTT_EXTRA,
       PTT_STRANGER, PTT_KEYS };

struct ptt_fixture {
    uint8_t seed[PTT_KEYS][32];
    uint8_t pub[PTT_KEYS][32];
    uint8_t verifiers[4][32]; /* A, B, C and (for attacks) one more */
    uint8_t extra[1][32];
    struct vcs_component_proof_key_v1 base;
    struct vcs_proof_candidate_domain domain;
    struct vcs_proof_reuse_policy policy;
};

static struct ptt_fixture g_ptt;

static void ptt_root(enum vcs_component_proof_field f, const char *text,
                     uint8_t out[32])
{
    if (!vcs_component_proof_field_root(f, text, strlen(text), out))
        memset(out, 0, 32);
}

static void ptt_fixture_init(void)
{
    memset(&g_ptt, 0, sizeof(g_ptt));
    for (int k = 0; k < PTT_KEYS; k++) {
        uint8_t sk[32];
        memset(g_ptt.seed[k], 0x11 * (k + 1), 32);
        g_ptt.seed[k][0] = (uint8_t)(0xA0 + k);
        zcl_ed25519_keypair(g_ptt.pub[k], sk, g_ptt.seed[k]);
    }
    memcpy(g_ptt.verifiers[0], g_ptt.pub[PTT_A], 32);
    memcpy(g_ptt.verifiers[1], g_ptt.pub[PTT_B], 32);
    memcpy(g_ptt.verifiers[2], g_ptt.pub[PTT_C], 32);
    memcpy(g_ptt.extra[0], g_ptt.pub[PTT_EXTRA], 32);
    for (int f = 0; f < VCS_CPK_FIELD_COUNT; f++) {
        char text[64];
        snprintf(text, sizeof(text), "base-%s",
                 vcs_component_proof_field_name((enum vcs_component_proof_field)f));
        ptt_root((enum vcs_component_proof_field)f, text, g_ptt.base.roots[f]);
    }
    memcpy(g_ptt.domain.author_pubkey, g_ptt.pub[PTT_AUTHOR], 32);
    g_ptt.domain.has_local_signer = true;
    memcpy(g_ptt.domain.local_signer_pubkey, g_ptt.pub[PTT_LOCAL], 32);
    g_ptt.domain.extra = (const uint8_t (*)[32])g_ptt.extra;
    g_ptt.domain.extra_count = 1;
    memcpy(g_ptt.policy.policy_root, g_ptt.base.roots[VCS_CPK_POLICY], 32);
    g_ptt.policy.verifiers = (const uint8_t (*)[32])g_ptt.verifiers;
    g_ptt.policy.verifier_count = 3;
    g_ptt.policy.quorum = 2;
}

struct ptt_ticket_spec {
    enum vcs_proof_verdict verdict;
    bool reproduced;
    int signer;
    uint64_t created;
};

static bool ptt_ticket(const struct vcs_component_proof_key_v1 *pre,
                       struct ptt_ticket_spec s,
                       uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES])
{
    struct vcs_proof_ticket_v1 t;
    memset(&t, 0, sizeof(t));
    t.verdict = s.verdict;
    t.reproduced = s.reproduced;
    if (!vcs_component_proof_key_derive(pre, t.input_key) ||
        !vcs_component_proof_key_preimage_root(pre, t.key_preimage_root))
        return false;
    memset(t.evidence_root, 0x5e, 32);
    t.evidence_root[0] = (uint8_t)s.signer;
    t.checks_run = 4;
    t.checks_passed = s.verdict == VCS_PROOF_VERDICT_PASS ? 4u : 3u;
    t.cpu_us = 1000;
    t.wall_us = 1200;
    t.bytes_in = 4096;
    t.bytes_out = 8192;
    t.created_unix = s.created ? s.created : 1790000000u;
    return vcs_proof_ticket_sign(&t, g_ptt.seed[s.signer]) &&
           vcs_proof_ticket_encode(&t, wire);
}

static struct ptt_ticket_spec ptt_pass(int signer)
{
    return (struct ptt_ticket_spec){VCS_PROOF_VERDICT_PASS, true, signer, 0};
}

static struct ptt_ticket_spec ptt_fail(int signer)
{
    return (struct ptt_ticket_spec){VCS_PROOF_VERDICT_FAIL, true, signer, 0};
}

/* Decide over up to 8 wires against the base fixture. */
static bool ptt_decide(const struct vcs_component_proof_key_v1 *local,
                       const struct vcs_proof_reuse_policy *policy,
                       uint8_t (*wires)[VCS_PROOF_TICKET_WIRE_BYTES],
                       size_t n, struct vcs_proof_ticket_class *classes,
                       struct vcs_proof_reuse_decision *out)
{
    const uint8_t *ptrs[8];
    size_t lens[8];
    for (size_t i = 0; i < n && i < 8; i++) {
        ptrs[i] = wires[i];
        lens[i] = VCS_PROOF_TICKET_WIRE_BYTES;
    }
    return vcs_proof_reuse_decide(local, &g_ptt.domain, policy, ptrs, lens,
                                  n, classes, out);
}

/* ── codec ─────────────────────────────────────────────────────────── */

static int ptt_case_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: preimage and ticket round-trip exactly") {
        uint8_t pre[VCS_CPK_WIRE_BYTES];
        struct vcs_component_proof_key_v1 back;
        ASSERT(vcs_component_proof_key_encode(&g_ptt.base, pre));
        ASSERT(vcs_component_proof_key_decode(pre, sizeof(pre), &back));
        ASSERT(memcmp(&back, &g_ptt.base, sizeof(back)) == 0);
        uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES], again[sizeof(wire)];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), wire));
        struct vcs_proof_ticket_v1 t;
        ASSERT(vcs_proof_ticket_decode(wire, sizeof(wire), &t));
        ASSERT(vcs_proof_ticket_signature_valid(&t));
        ASSERT(vcs_proof_ticket_encode(&t, again));
        ASSERT(memcmp(wire, again, sizeof(wire)) == 0);
        uint8_t fail[VCS_PROOF_TICKET_WIRE_BYTES], r1[32], r2[32];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_fail(PTT_A), fail));
        ASSERT(vcs_proof_ticket_observation_root(wire, sizeof(wire), r1));
        ASSERT(vcs_proof_ticket_observation_root(fail, sizeof(fail), r2));
        ASSERT(memcmp(r1, r2, 32) != 0);
        ASSERT(memcmp(wire + 16, fail + 16, 32) == 0); /* same input key */
    } TEST_END
    return failures;
}

static bool ptt_decode_mutant(const uint8_t *wire, size_t len, size_t at,
                              uint8_t value)
{
    uint8_t m[VCS_PROOF_TICKET_WIRE_BYTES + 1];
    memcpy(m, wire, len <= VCS_PROOF_TICKET_WIRE_BYTES ? len :
                                                         VCS_PROOF_TICKET_WIRE_BYTES);
    if (len > VCS_PROOF_TICKET_WIRE_BYTES) m[VCS_PROOF_TICKET_WIRE_BYTES] = 0;
    if (at < len) m[at] = value;
    struct vcs_proof_ticket_v1 t;
    return vcs_proof_ticket_decode(m, len, &t);
}

static int ptt_case_wire_refusals(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: truncated/extended/non-canonical wire refused") {
        uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), wire));
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire) - 1, SIZE_MAX, 0));
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire) + 1, SIZE_MAX, 0));
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire), 0, 'X'));   /* magic */
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire), 8, 2));     /* version */
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire), 12, 3));    /* verdict */
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire), 13, 2));    /* reproduced */
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire), 14, 1));    /* reserved */
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire), 116, 3));   /* PASS 3/4 */
        ASSERT(!ptt_decode_mutant(wire, sizeof(wire), 112, 0));   /* 0 run */
        struct vcs_proof_ticket_v1 t;
        ASSERT(!vcs_proof_ticket_decode(NULL, 0, &t));
        uint8_t pre[VCS_CPK_WIRE_BYTES + 1];
        struct vcs_component_proof_key_v1 k;
        ASSERT(vcs_component_proof_key_encode(&g_ptt.base, pre));
        pre[VCS_CPK_WIRE_BYTES] = 0;
        ASSERT(!vcs_component_proof_key_decode(pre, VCS_CPK_WIRE_BYTES + 1, &k));
        ASSERT(!vcs_component_proof_key_decode(pre, VCS_CPK_WIRE_BYTES - 1, &k));
        pre[12] = 14;
        ASSERT(!vcs_component_proof_key_decode(pre, VCS_CPK_WIRE_BYTES, &k));
    } TEST_END
    return failures;
}

static int ptt_case_environment(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: environment root binds allowlisted names+values") {
        struct vcs_component_proof_env env[2] = {{"CC", "cc"}, {"LANG", "C"}};
        struct vcs_component_proof_env unset[2] = {{"CC", "cc"}, {"LANG", NULL}};
        struct vcs_component_proof_env empty[2] = {{"CC", "cc"}, {"LANG", ""}};
        struct vcs_component_proof_env unsorted[2] = {{"LANG", "C"}, {"CC", "cc"}};
        struct vcs_component_proof_env lower[1] = {{"path", "/bin"}};
        uint8_t a[32], b[32], c[32], d[32];
        ASSERT(vcs_component_proof_environment_root(env, 2, a));
        ASSERT(vcs_component_proof_environment_root(unset, 2, b));
        ASSERT(vcs_component_proof_environment_root(empty, 2, c));
        ASSERT(memcmp(a, b, 32) != 0 && memcmp(b, c, 32) != 0);
        ASSERT(!vcs_component_proof_environment_root(unsorted, 2, d));
        ASSERT(!vcs_component_proof_environment_root(lower, 1, d));
        ASSERT(vcs_component_proof_field_root(VCS_CPK_TARGET, "x", 1, c));
        ASSERT(vcs_component_proof_field_root(VCS_CPK_FLAGS, "x", 1, d));
        ASSERT(memcmp(c, d, 32) != 0);
    } TEST_END
    return failures;
}

/* ── false-hit regressions ─────────────────────────────────────────── */

static int ptt_case_baseline_hit(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: two independent verifiers reach HIT") {
        uint8_t w[2][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_B), w[1]));
        struct vcs_proof_ticket_class cls[2];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &g_ptt.policy, w, 2, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.used_count, 2u);
        ASSERT_EQ(d.distinct_pass_signers, 2u);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_ELIGIBLE);
    } TEST_END
    return failures;
}

/* One field, one flipped byte: the old quorum must not HIT. */
static int ptt_case_field(int f)
{
    int failures = 0;
    char name[128];
    const char *field = vcs_component_proof_field_name((enum vcs_component_proof_field)f);
    snprintf(name, sizeof(name),
             "proof_ticket: one byte of %s changed -> MISS", field);
    TEST_CASE(name) {
        uint8_t w[2][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_B), w[1]));
        struct vcs_component_proof_key_v1 local = g_ptt.base;
        local.roots[f][31] ^= 0x01;
        ASSERT_EQ(vcs_component_proof_key_diff(&g_ptt.base, &local), 1u << f);
        uint8_t k0[32], k1[32];
        ASSERT(vcs_component_proof_key_derive(&g_ptt.base, k0));
        ASSERT(vcs_component_proof_key_derive(&local, k1));
        ASSERT(memcmp(k0, k1, 32) != 0);
        struct vcs_proof_reuse_policy policy = g_ptt.policy;
        memcpy(policy.policy_root, local.roots[VCS_CPK_POLICY], 32);
        struct vcs_proof_ticket_class cls[2];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&local, &policy, w, 2, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_INELIGIBLE);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_KEY_MISMATCH);
        ASSERT_STR_EQ(cls[1].reason, VCS_PROOF_TICKET_KEY_MISMATCH);
    } TEST_END
    return failures;
}

static int ptt_case_forged(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: forged signature retained, never authorizes") {
        uint8_t w[3][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_B), w[1]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_fail(PTT_C), w[2]));
        w[0][200] ^= 0x40; /* forge A's PASS */
        w[2][200] ^= 0x40; /* forge C's FAIL */
        struct vcs_proof_ticket_class cls[3];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &g_ptt.policy, w, 3, cls, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_SIGNATURE_INVALID);
        ASSERT_STR_EQ(cls[2].reason, VCS_PROOF_TICKET_SIGNATURE_INVALID);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_EQ(d.eligible_fail, 0u); /* the forged FAIL blocks nothing */
    } TEST_END
    return failures;
}

/* A signer inside the candidate domain is refused even when the receiver
 * also lists it as a verifier. */
static int ptt_case_domain_signer(int who, const char *label)
{
    int failures = 0;
    char name[128];
    snprintf(name, sizeof(name), "proof_ticket: %s signer refused for reuse",
             label);
    TEST_CASE(name) {
        struct vcs_proof_reuse_policy policy = g_ptt.policy;
        uint8_t verifiers[4][32];
        memcpy(verifiers, g_ptt.verifiers, sizeof(verifiers));
        memcpy(verifiers[3], g_ptt.pub[who], 32);
        policy.verifiers = (const uint8_t (*)[32])verifiers;
        policy.verifier_count = 4;
        policy.quorum = 1;
        uint8_t w[2][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(who), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_fail(who), w[1]));
        struct vcs_proof_ticket_class cls[2];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &policy, w, 2, cls, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_SIGNER_IN_DOMAIN);
        ASSERT_STR_EQ(cls[1].reason, VCS_PROOF_TICKET_SIGNER_IN_DOMAIN);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

static int ptt_case_untrusted_and_copied(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: stranger and unreproduced tickets ineligible") {
        uint8_t w[3][VCS_PROOF_TICKET_WIRE_BYTES];
        struct ptt_ticket_spec copied = ptt_pass(PTT_A);
        copied.reproduced = false;
        struct ptt_ticket_spec copied_b = ptt_pass(PTT_B);
        copied_b.reproduced = false;
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_STRANGER), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, copied, w[1]));
        ASSERT(ptt_ticket(&g_ptt.base, copied_b, w[2]));
        struct vcs_proof_ticket_class cls[3];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &g_ptt.policy, w, 3, cls, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_SIGNER_UNTRUSTED);
        ASSERT_STR_EQ(cls[1].reason, VCS_PROOF_TICKET_NOT_REPRODUCED);
        ASSERT_STR_EQ(cls[2].reason, VCS_PROOF_TICKET_NOT_REPRODUCED);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

static int ptt_case_conflict(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: eligible PASS+FAIL refuses, both roots indexed") {
        uint8_t w[3][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_B), w[1]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_fail(PTT_C), w[2]));
        struct vcs_proof_ticket_index index;
        vcs_proof_ticket_index_init(&index);
        bool added = false;
        for (int i = 0; i < 3; i++) {
            ASSERT(vcs_proof_ticket_index_add(&index, w[i], sizeof(w[i]),
                                              &added));
            ASSERT(added);
        }
        ASSERT(vcs_proof_ticket_index_add(&index, w[2], sizeof(w[2]), &added));
        ASSERT(!added); /* set semantics, nothing overwritten */
        struct vcs_proof_ticket_class cls[8];
        struct vcs_proof_reuse_decision d;
        bool ok = vcs_proof_reuse_decide_index(&g_ptt.base, &g_ptt.domain,
                                               &g_ptt.policy, &index, cls, 8,
                                               &d);
        size_t kept = vcs_proof_ticket_index_lookup(&index, d.input_key,
                                                    NULL, 0);
        vcs_proof_ticket_index_free(&index);
        ASSERT(ok);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT_EQ(d.used_count, 3u);
        ASSERT_EQ(kept, (size_t)3);
    } TEST_END
    return failures;
}

static int ptt_case_known_fail(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: an eligible FAIL alone is HIT_FAIL") {
        uint8_t w[1][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_fail(PTT_B), w[0]));
        struct vcs_proof_ticket_class cls[1];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &g_ptt.policy, w, 1, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_FAIL);
        ASSERT_EQ(d.used_count, 1u);
    } TEST_END
    return failures;
}

/* A ticket signed by a trusted verifier that claims the local key over a
 * different preimage, or the local preimage under a different key. */
static int ptt_case_key_lies(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: ticket key must be its preimage's key") {
        struct vcs_component_proof_key_v1 other = g_ptt.base;
        other.roots[VCS_CPK_SOURCE_CLOSURE][0] ^= 0x80;
        struct vcs_proof_ticket_v1 t[2];
        uint8_t w[2][VCS_PROOF_TICKET_WIRE_BYTES];
        for (int i = 0; i < 2; i++) {
            ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(i == 0 ? PTT_A : PTT_B), w[i]));
            ASSERT(vcs_proof_ticket_decode(w[i], sizeof(w[i]), &t[i]));
        }
        ASSERT(vcs_component_proof_key_preimage_root(&other,
                                                     t[0].key_preimage_root));
        memset(t[1].input_key, 0x33, 32);
        for (int i = 0; i < 2; i++) {
            ASSERT(vcs_proof_ticket_sign(&t[i], g_ptt.seed[i == 0 ? PTT_A : PTT_B]));
            ASSERT(vcs_proof_ticket_encode(&t[i], w[i]));
        }
        struct vcs_proof_ticket_class cls[2];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &g_ptt.policy, w, 2, cls, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_PREIMAGE_MISMATCH);
        ASSERT_STR_EQ(cls[1].reason, VCS_PROOF_TICKET_KEY_MISMATCH);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

static int ptt_case_policy_change(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: receiver policy change -> MISS; mismatch refused") {
        uint8_t w[2][VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_B), w[1]));
        struct vcs_component_proof_key_v1 local = g_ptt.base;
        ptt_root(VCS_CPK_POLICY, "policy-v2", local.roots[VCS_CPK_POLICY]);
        struct vcs_proof_reuse_policy policy = g_ptt.policy;
        memcpy(policy.policy_root, local.roots[VCS_CPK_POLICY], 32);
        struct vcs_proof_ticket_class cls[2];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&local, &policy, w, 2, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        /* Deciding the OLD preimage under the NEW policy is ambiguous. */
        ASSERT(!ptt_decide(&g_ptt.base, &policy, w, 2, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_POLICY_ROOT);
        policy = g_ptt.policy;
        policy.quorum = 0;
        ASSERT(!ptt_decide(&g_ptt.base, &policy, w, 2, cls, &d));
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_POLICY);
    } TEST_END
    return failures;
}

static int ptt_case_quorum_one_signer(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: quorum 2 with one signer twice is not HIT") {
        uint8_t w[3][VCS_PROOF_TICKET_WIRE_BYTES];
        struct ptt_ticket_spec later = ptt_pass(PTT_A);
        later.created = 1790000100u;
        ASSERT(ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, later, w[1]));
        memcpy(w[2], w[0], sizeof(w[0])); /* exact duplicate too */
        struct vcs_proof_ticket_class cls[3];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &g_ptt.policy, w, 3, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_EQ(d.distinct_pass_signers, 1u);
        ASSERT_STR_EQ(cls[2].reason, VCS_PROOF_TICKET_DUPLICATE);
    } TEST_END
    return failures;
}

static int ptt_case_freshness(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: stale and future tickets ineligible") {
        uint8_t w[2][VCS_PROOF_TICKET_WIRE_BYTES];
        struct ptt_ticket_spec old = ptt_pass(PTT_A);
        old.created = 1000;
        struct ptt_ticket_spec future = ptt_pass(PTT_B);
        future.created = 1790009999u;
        ASSERT(ptt_ticket(&g_ptt.base, old, w[0]));
        ASSERT(ptt_ticket(&g_ptt.base, future, w[1]));
        struct vcs_proof_reuse_policy policy = g_ptt.policy;
        policy.now_unix = 1790000000u;
        policy.max_age_seconds = 86400u;
        policy.max_future_seconds = 300u;
        struct vcs_proof_ticket_class cls[2];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_ptt.base, &policy, w, 2, cls, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_STALE);
        ASSERT_STR_EQ(cls[1].reason, VCS_PROOF_TICKET_FUTURE);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

/* ── CAS projection ─────────────────────────────────────────────────── */

static bool ptt_store_all(struct vcs_package_store *store,
                          uint8_t (*w)[VCS_PROOF_TICKET_WIRE_BYTES], size_t n,
                          uint8_t pre_root[32])
{
    uint8_t pre[VCS_CPK_WIRE_BYTES], root[32], expect[32];
    if (!vcs_component_proof_key_encode(&g_ptt.base, pre) ||
        !vcs_proof_ticket_store_put(store, pre, sizeof(pre), pre_root) ||
        !vcs_component_proof_key_preimage_root(&g_ptt.base, expect) ||
        memcmp(expect, pre_root, 32) != 0)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!vcs_proof_ticket_store_put(store, w[i], sizeof(w[i]), root))
            return false;
    return true;
}

static int ptt_case_cas_rebuild(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: index is a projection rebuilt from CAS blobs") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "cas");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        uint8_t w[2][VCS_PROOF_TICKET_WIRE_BYTES], pre_root[32];
        bool ok = ptt_ticket(&g_ptt.base, ptt_pass(PTT_A), w[0]) &&
                  ptt_ticket(&g_ptt.base, ptt_fail(PTT_C), w[1]) &&
                  ptt_store_all(store, w, 2, pre_root);
        struct vcs_proof_ticket_index index;
        vcs_proof_ticket_index_init(&index);
        size_t added = 0, skipped = 0;
        ok = ok && vcs_proof_ticket_index_rebuild(&index, store, &added,
                                                  &skipped);
        struct vcs_component_proof_key_v1 loaded;
        ok = ok && vcs_component_proof_key_load(store, pre_root, &loaded);
        uint8_t key[32];
        ok = ok && vcs_component_proof_key_derive(&loaded, key);
        size_t kept = vcs_proof_ticket_index_lookup(&index, key, NULL, 0);
        vcs_proof_ticket_index_free(&index);
        vcs_package_store_close(store);
        test_rm_rf(dir);
        ASSERT(ok);
        ASSERT_EQ(added, (size_t)2);
        ASSERT_EQ(skipped, (size_t)1); /* the preimage blob */
        ASSERT_EQ(kept, (size_t)2);
        ASSERT(memcmp(&loaded, &g_ptt.base, sizeof(loaded)) == 0);
    } TEST_END
    return failures;
}

/* ── measurement ────────────────────────────────────────────────────── */

#define PTM_UNITS 200u
#define PTM_CANDIDATES 6u      /* one cold baseline + five candidates */
#define PTM_HEADER_UNITS 60u   /* units that include the shared header */
#define PTM_FLAKY_UNIT 17u     /* machine C once reports FAIL here */
#define PTM_BROKEN_UNIT 42u    /* truly fails at odd source versions */

struct ptm_state {
    uint32_t version[PTM_UNITS];
    uint32_t header;
    uint64_t rng;
    struct vcs_proof_ticket_index index;
    uint32_t candidate;
    uint32_t machine_turn;
    /* results */
    uint64_t decisions, hit, rerun, refused, known_fail, false_hits;
    uint64_t domain_leaks, tickets_signed;
    uint64_t ticket_bytes, artifact_bytes_avoided;
    int64_t *verify_us;
    size_t verify_n;
};

static uint32_t ptm_rand(struct ptm_state *s)
{
    s->rng = s->rng * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(s->rng >> 33);
}

static uint64_t ptm_artifact_bytes(uint32_t u)
{
    return 16384u + (uint64_t)((u * 2654435761u) % 196608u);
}

static bool ptm_truly_passes(uint32_t u, uint32_t version)
{
    return !(u == PTM_BROKEN_UNIT && (version & 1u));
}

static void ptm_preimage(const struct ptm_state *s, uint32_t u,
                         struct vcs_component_proof_key_v1 *k)
{
    char text[96];
    *k = g_ptt.base;
    snprintf(text, sizeof(text), "unit/%u", u);
    ptt_root(VCS_CPK_UNIT_ID, text, k->roots[VCS_CPK_UNIT_ID]);
    snprintf(text, sizeof(text), "src/%u@%u", u, s->version[u]);
    ptt_root(VCS_CPK_SOURCE_CLOSURE, text, k->roots[VCS_CPK_SOURCE_CLOSURE]);
    if (u < PTM_HEADER_UNITS) {
        snprintf(text, sizeof(text), "shared.h@%u", s->header);
        ptt_root(VCS_CPK_DEPENDENCY_CLOSURE, text,
                 k->roots[VCS_CPK_DEPENDENCY_CLOSURE]);
        ptt_root(VCS_CPK_INTEGRATION_EDGES, text,
                 k->roots[VCS_CPK_INTEGRATION_EDGES]);
    }
}

static bool ptm_emit(struct ptm_state *s,
                     const struct vcs_component_proof_key_v1 *k,
                     struct ptt_ticket_spec spec)
{
    uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
    spec.created = 1790000000u + s->candidate;
    if (!ptt_ticket(k, spec, wire)) return false;
    s->tickets_signed++;
    return vcs_proof_ticket_index_add(&s->index, wire, sizeof(wire), NULL);
}

/* Two of the three machines reproduce the unit independently. */
static bool ptm_rerun(struct ptm_state *s, uint32_t u,
                      const struct vcs_component_proof_key_v1 *k)
{
    bool pass = ptm_truly_passes(u, s->version[u]);
    for (int i = 0; i < 2; i++) {
        int m = (int)((s->machine_turn++) % 3u);
        struct ptt_ticket_spec spec = pass ? ptt_pass(m) : ptt_fail(m);
        if (!ptm_emit(s, k, spec)) return false;
    }
    return true;
}

static void ptm_audit(struct ptm_state *s, uint32_t u,
                      const struct vcs_proof_ticket_class *cls, size_t n,
                      const struct vcs_proof_reuse_decision *d)
{
    for (size_t i = 0; i < n; i++) {
        if (!cls[i].eligible) continue;
        bool trusted = false;
        for (int m = 0; m < 3; m++)
            trusted |= memcmp(cls[i].producer_pubkey, g_ptt.pub[m], 32) == 0;
        if (!trusted) s->domain_leaks++;
    }
    if (d->outcome == VCS_PROOF_REUSE_HIT_PASS &&
        (!ptm_truly_passes(u, s->version[u]) || d->distinct_pass_signers < 2))
        s->false_hits++;
}

static void ptm_record_cost(struct ptm_state *s, int64_t us, uint32_t seen)
{
    if (seen == 0) return;
    s->verify_us[s->verify_n++] = us / (int64_t)seen;
    s->ticket_bytes += (uint64_t)seen * VCS_PROOF_TICKET_WIRE_BYTES;
}

static bool ptm_account(struct ptm_state *s, uint32_t u,
                        const struct vcs_component_proof_key_v1 *k,
                        const struct vcs_proof_reuse_decision *d)
{
    switch (d->outcome) {
    case VCS_PROOF_REUSE_HIT_PASS:
        s->hit++;
        s->artifact_bytes_avoided += ptm_artifact_bytes(u);
        return true;
    case VCS_PROOF_REUSE_HIT_FAIL:
        s->known_fail++;
        return true;
    case VCS_PROOF_REUSE_REFUSE:
        s->refused++;
        return true;
    case VCS_PROOF_REUSE_MISS:
        s->rerun++;
        return ptm_rerun(s, u, k);
    }
    return false;
}

static bool ptm_unit(struct ptm_state *s, uint32_t u)
{
    struct vcs_component_proof_key_v1 k;
    ptm_preimage(s, u, &k);
    struct vcs_proof_ticket_class cls[64];
    struct vcs_proof_reuse_decision d;
    int64_t t0 = platform_time_monotonic_us();
    bool ok = vcs_proof_reuse_decide_index(&k, &g_ptt.domain, &g_ptt.policy,
                                           &s->index, cls, 64, &d);
    ptm_record_cost(s, platform_time_monotonic_us() - t0, d.tickets_seen);
    if (!ok) return false;
    s->decisions++;
    ptm_audit(s, u, cls, d.tickets_seen, &d);
    return ptm_account(s, u, &k, &d);
}

/* The candidate author and the same-uid local signer both "prove" every
 * unit they touched; C once disagrees with an honest PASS. */
static bool ptm_attack(struct ptm_state *s, uint32_t u)
{
    struct vcs_component_proof_key_v1 k;
    ptm_preimage(s, u, &k);
    if (!ptm_emit(s, &k, ptt_pass(PTT_AUTHOR)) ||
        !ptm_emit(s, &k, ptt_pass(PTT_LOCAL)))
        return false;
    if (u == PTM_FLAKY_UNIT && s->candidate == 4)
        return ptm_emit(s, &k, ptt_pass(PTT_A)) &&
               ptm_emit(s, &k, ptt_fail(PTT_C));
    return true;
}

static bool ptm_candidate(struct ptm_state *s)
{
    static const uint32_t change_pct10[PTM_CANDIDATES] = {0, 10, 30, 50, 70,
                                                          100};
    uint32_t changes = PTM_UNITS * change_pct10[s->candidate] / 1000u;
    for (uint32_t i = 0; i < changes; i++) {
        uint32_t u = ptm_rand(s) % PTM_UNITS;
        s->version[u]++;
        if (!ptm_attack(s, u)) return false;
    }
    if (s->candidate == 4 && !ptm_attack(s, PTM_FLAKY_UNIT)) return false;
    if (s->candidate == 3) s->header++; /* one shared header edit */
    for (uint32_t u = 0; u < PTM_UNITS; u++)
        if (!ptm_unit(s, u)) return false;
    return true;
}

static int ptm_cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static void ptm_print(struct ptm_state *s, uint64_t warm_units)
{
    int64_t median = 0;
    if (s->verify_n) {
        qsort(s->verify_us, s->verify_n, sizeof(int64_t), ptm_cmp_i64);
        median = s->verify_us[s->verify_n / 2];
    }
    printf("\nproof_ticket_reuse_measure candidates=%u machines=3 units=%u "
           "units_total=%llu hit=%llu rerun=%llu refused=%llu known_fail=%llu "
           "hit_rate_warm_pct=%.2f ticket_bytes=%llu tickets_signed=%llu "
           "artifact_bytes_avoided=%llu verify_us_median=%lld "
           "false_hits=%llu domain_leaks=%llu\n",
           PTM_CANDIDATES, PTM_UNITS, (unsigned long long)s->decisions,
           (unsigned long long)s->hit, (unsigned long long)s->rerun,
           (unsigned long long)s->refused, (unsigned long long)s->known_fail,
           warm_units ? 100.0 * (double)s->hit / (double)warm_units : 0.0,
           (unsigned long long)s->ticket_bytes,
           (unsigned long long)s->tickets_signed,
           (unsigned long long)s->artifact_bytes_avoided, (long long)median,
           (unsigned long long)s->false_hits,
           (unsigned long long)s->domain_leaks);
}

static int ptt_case_measure(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: 6 candidates x 3 verifiers x 200 units") {
        struct ptm_state *s = calloc(1, sizeof(*s));
        ASSERT(s != NULL);
        s->rng = 0x5eed1234abcdull;
        s->verify_us = calloc(PTM_UNITS * PTM_CANDIDATES, sizeof(int64_t));
        vcs_proof_ticket_index_init(&s->index);
        bool ok = s->verify_us != NULL;
        for (s->candidate = 0; ok && s->candidate < PTM_CANDIDATES;
             s->candidate++)
            ok = ptm_candidate(s);
        ptm_print(s, s->decisions - PTM_UNITS);
        struct ptm_state r = *s;
        vcs_proof_ticket_index_free(&s->index);
        free(s->verify_us);
        free(s);
        ASSERT(ok);
        ASSERT_EQ(r.decisions, (uint64_t)PTM_UNITS * PTM_CANDIDATES);
        ASSERT_EQ(r.false_hits, 0u);
        ASSERT_EQ(r.domain_leaks, 0u);
        ASSERT(r.refused >= 1u);       /* the injected contradiction */
        ASSERT(r.hit > r.rerun);       /* reuse dominates after warm-up */
    } TEST_END
    return failures;
}

int test_proof_ticket_reuse(void);

int test_proof_ticket_reuse(void)
{
    int failures = 0;
    ptt_fixture_init();
    failures += ptt_case_roundtrip();
    failures += ptt_case_wire_refusals();
    failures += ptt_case_environment();
    failures += ptt_case_baseline_hit();
    for (int f = 0; f < VCS_CPK_FIELD_COUNT; f++)
        failures += ptt_case_field(f);
    failures += ptt_case_forged();
    failures += ptt_case_domain_signer(PTT_AUTHOR, "candidate author");
    failures += ptt_case_domain_signer(PTT_LOCAL, "same-uid local proof");
    failures += ptt_case_domain_signer(PTT_EXTRA, "candidate-domain extra");
    failures += ptt_case_untrusted_and_copied();
    failures += ptt_case_conflict();
    failures += ptt_case_known_fail();
    failures += ptt_case_key_lies();
    failures += ptt_case_policy_change();
    failures += ptt_case_quorum_one_signer();
    failures += ptt_case_freshness();
    failures += ptt_case_cas_rebuild();
    failures += ptt_case_measure();
    return failures;
}
