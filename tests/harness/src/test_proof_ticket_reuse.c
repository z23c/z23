/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: False-hit regressions for component proof keys, signed proof
 *          tickets, issuer checkpoints and the receiver reuse decision.
 *
 * Every case guards one way a reused proof could claim work it never
 * covered: one changed byte in any of the nineteen key fields, reordered
 * flags, an uncheckpointed or forged ticket, a candidate-domain or
 * same-uid signer, a reused (not executed) basis, a revoked verifier, an
 * equivocating issuer, a contradiction, a ticket whose key is not its
 * preimage, tampered artifact bytes, malformed wire, a policy change and a
 * one-signer quorum. The deterministic measurement lives in
 * test_proof_ticket_measure.c. */

#include "test/test_core.h"

#include "chain/mmr.h"
#include "test/proof_ticket_fixture.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <string.h>

static struct ptf g_f;

#define PTT_CLASS_CAP 16u

/* Emit from each listed signer and sync each of their logs. */
static bool ptt_emit_sync(const struct vcs_component_proof_key_v1 *key,
                          struct ptf_spec spec, const int *signers, size_t n)
{
    struct vcs_proof_sync_report rep;
    for (size_t i = 0; i < n; i++)
        if (!ptf_emit(&g_f, signers[i], key, spec, NULL, NULL) ||
            !ptf_sync(&g_f, signers[i], 0, &rep) ||
            rep.outcome != VCS_PROOF_SYNC_ADVANCED)
            return false;
    return true;
}

static bool ptt_fresh(void)
{
    ptf_free(&g_f);
    return ptf_init(&g_f);
}

static bool ptt_decide(const struct vcs_component_proof_key_v1 *key,
                       enum vcs_proof_action_class cls,
                       const struct vcs_proof_reuse_policy *policy,
                       struct vcs_proof_ticket_class *classes,
                       struct vcs_proof_reuse_decision *d)
{
    return ptf_decide(&g_f, key, cls, policy, classes, PTT_CLASS_CAP, d);
}

/* Index of the class whose producer is `signer`, or -1. */
static int ptt_class_of(const struct vcs_proof_ticket_class *c, uint32_t n,
                        int signer)
{
    for (uint32_t i = 0; i < n; i++)
        if (memcmp(c[i].producer_pubkey, g_f.pub[signer], 32) == 0)
            return (int)i;
    return -1;
}

static const char *ptt_reason_of(const struct vcs_proof_ticket_class *c,
                                 uint32_t n, int signer)
{
    int i = ptt_class_of(c, n, signer);
    return i < 0 ? "(absent)" : c[i].reason;
}

/* ── codecs ─────────────────────────────────────────────────────────── */

static int ptt_case_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: preimage, ticket, checkpoint round-trip") {
        ASSERT(ptt_fresh());
        uint8_t pre[VCS_CPK_WIRE_BYTES];
        struct vcs_component_proof_key_v1 back;
        ASSERT(vcs_component_proof_key_encode(&g_f.base, pre));
        ASSERT(vcs_component_proof_key_decode(pre, sizeof(pre), &back));
        ASSERT(memcmp(&back, &g_f.base, sizeof(back)) == 0);
        uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES], again[sizeof(wire)];
        ASSERT(ptf_emit(&g_f, PTF_A, &g_f.base, ptf_pass(), wire, NULL));
        struct vcs_proof_ticket_v1 t;
        ASSERT(vcs_proof_ticket_decode(wire, sizeof(wire), &t));
        ASSERT(vcs_proof_ticket_signature_valid(&t));
        ASSERT(vcs_proof_ticket_encode(&t, again));
        ASSERT(memcmp(wire, again, sizeof(wire)) == 0);
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES], cp2[sizeof(cp)];
        struct vcs_proof_checkpoint_v1 c;
        ASSERT(vcs_proof_issuer_log_checkpoint(g_f.logs[PTF_A], 7, cp));
        ASSERT(vcs_proof_checkpoint_decode(cp, sizeof(cp), &c));
        ASSERT(vcs_proof_checkpoint_signature_valid(&c));
        ASSERT(vcs_proof_checkpoint_encode(&c, cp2));
        ASSERT(memcmp(cp, cp2, sizeof(cp)) == 0);
        ASSERT_EQ(c.leaf_count, (uint64_t)1);
    } TEST_END
    return failures;
}

static bool ptt_ticket_decodes(const uint8_t *wire, size_t len, size_t at,
                               uint8_t value)
{
    uint8_t m[VCS_PROOF_TICKET_WIRE_BYTES + 1] = {0};
    memcpy(m, wire, len < VCS_PROOF_TICKET_WIRE_BYTES ? len :
                                                        VCS_PROOF_TICKET_WIRE_BYTES);
    if (at < len) m[at] = value;
    struct vcs_proof_ticket_v1 t;
    return vcs_proof_ticket_decode(m, len, &t);
}

static int ptt_case_ticket_refusals(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: truncated/extended/non-canonical ticket refused") {
        ASSERT(ptt_fresh());
        uint8_t w[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_f, PTF_A, &g_f.base, ptf_pass(), w, NULL));
        size_t n = sizeof(w);
        ASSERT(ptt_ticket_decodes(w, n, SIZE_MAX, 0));
        ASSERT(!ptt_ticket_decodes(w, n - 1, SIZE_MAX, 0));
        ASSERT(!ptt_ticket_decodes(w, n + 1, SIZE_MAX, 0));
        ASSERT(!ptt_ticket_decodes(w, n, 0, 'X'));    /* magic */
        ASSERT(!ptt_ticket_decodes(w, n, 8, 2));      /* version */
        ASSERT(!ptt_ticket_decodes(w, n, 12, 3));     /* verdict */
        ASSERT(!ptt_ticket_decodes(w, n, 13, 3));     /* basis */
        ASSERT(!ptt_ticket_decodes(w, n, 13, 2));     /* REUSED, no ref */
        ASSERT(!ptt_ticket_decodes(w, n, 14, 1));     /* CHECK->BUILD, no art */
        ASSERT(!ptt_ticket_decodes(w, n, 15, 1));     /* reserved */
        ASSERT(!ptt_ticket_decodes(w, n, 112, 1));    /* CHECK with artifact */
        ASSERT(!ptt_ticket_decodes(w, n, 212, 3));    /* PASS 3/4 */
        ASSERT(!ptt_ticket_decodes(w, n, 208, 0));    /* zero checks */
    } TEST_END
    return failures;
}

static int ptt_case_other_refusals(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: preimage and checkpoint framing refused") {
        ASSERT(ptt_fresh());
        uint8_t pre[VCS_CPK_WIRE_BYTES + 1] = {0};
        struct vcs_component_proof_key_v1 k;
        ASSERT(vcs_component_proof_key_encode(&g_f.base, pre));
        ASSERT(!vcs_component_proof_key_decode(pre, sizeof(pre), &k));
        ASSERT(!vcs_component_proof_key_decode(pre, sizeof(pre) - 2, &k));
        pre[12] = 15; /* the old field count */
        ASSERT(!vcs_component_proof_key_decode(pre, VCS_CPK_WIRE_BYTES, &k));
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES + 1] = {0};
        struct vcs_proof_checkpoint_v1 c;
        ASSERT(ptf_emit(&g_f, PTF_A, &g_f.base, ptf_pass(), NULL, NULL));
        ASSERT(vcs_proof_issuer_log_checkpoint(g_f.logs[PTF_A], 7, cp));
        ASSERT(!vcs_proof_checkpoint_decode(cp, sizeof(cp), &c));
        ASSERT(!vcs_proof_checkpoint_decode(cp, sizeof(cp) - 2, &c));
        cp[12] = 1;
        ASSERT(!vcs_proof_checkpoint_decode(cp, sizeof(cp) - 1, &c));
    } TEST_END
    return failures;
}

static int ptt_case_field_helpers(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: env, ordered, generated roots are canonical") {
        struct vcs_component_proof_env env[2] = {{"CC", "cc"}, {"LANG", "C"}};
        struct vcs_component_proof_env unset[2] = {{"CC", "cc"}, {"LANG", NULL}};
        struct vcs_component_proof_env unsorted[2] = {{"LANG", "C"}, {"CC", "cc"}};
        uint8_t a[32], b[32];
        ASSERT(vcs_component_proof_environment_root(env, 2, a));
        ASSERT(vcs_component_proof_environment_root(unset, 2, b));
        ASSERT(memcmp(a, b, 32) != 0);
        ASSERT(!vcs_component_proof_environment_root(unsorted, 2, b));
        const char *argv[3] = {"-O2", "-DNDEBUG", "-Wall"};
        const char *swapped[3] = {"-DNDEBUG", "-O2", "-Wall"};
        ASSERT(vcs_component_proof_ordered_root(VCS_CPK_FLAGS, argv, 3, a));
        ASSERT(vcs_component_proof_ordered_root(VCS_CPK_FLAGS, swapped, 3, b));
        ASSERT(memcmp(a, b, 32) != 0);
        struct vcs_component_proof_generated gen[2] = {
            {"b/gen.h", {1}, {2}}, {"a/gen.h", {3}, {4}}};
        ASSERT(!vcs_component_proof_generated_root(gen, 2, a));
        ASSERT(vcs_component_proof_generated_root(gen + 1, 1, a));
    } TEST_END
    return failures;
}

static int ptt_case_contract(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: contract and edge roots bind interface only") {
        const char *tokens[3] = {"int", "f", "(void);"};
        const char *syms[2] = {"f:v->i", "g:i->v"};
        const char *syms_rev[2] = {"g:i->v", "f:v->i"};
        const char *dup[2] = {"f:v->i", "f:v->i"};
        struct vcs_component_contract c = {"libA", tokens, 3, syms, 2, NULL, 0};
        uint8_t r1[32], r2[32], e1[32], e2[32];
        ASSERT(vcs_component_contract_root(&c, r1));
        c.symbols = syms_rev;
        ASSERT(vcs_component_contract_root(&c, r2));
        ASSERT(memcmp(r1, r2, 32) == 0); /* a set, not a list */
        c.symbols = dup;
        ASSERT(!vcs_component_contract_root(&c, r2));
        c.symbols = syms;
        c.header_token_count = 2;
        ASSERT(vcs_component_contract_root(&c, r2));
        ASSERT(memcmp(r1, r2, 32) != 0);
        struct vcs_component_edge edges[2] = {{"libB", {0}}, {"libA", {0}}};
        memcpy(edges[0].contract_root, r2, 32);
        memcpy(edges[1].contract_root, r1, 32);
        ASSERT(vcs_component_integration_edges_root(edges, 2, e1));
        struct vcs_component_edge rev[2] = {edges[1], edges[0]};
        ASSERT(vcs_component_integration_edges_root(rev, 2, e2));
        ASSERT(memcmp(e1, e2, 32) == 0);
        rev[1].callee_id = "libA";
        ASSERT(!vcs_component_integration_edges_root(rev, 2, e2));
    } TEST_END
    return failures;
}

/* ── decisions ──────────────────────────────────────────────────────── */

static const int PTT_AB[2] = {PTF_A, PTF_B};

static int ptt_case_baseline_hit(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: two checkpointed independent verifiers HIT") {
        ASSERT(ptt_fresh());
        ASSERT(ptt_emit_sync(&g_f.base, ptf_pass(), PTT_AB, 2));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.used_count, 2u);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_ELIGIBLE);
    } TEST_END
    return failures;
}

/* One field, one flipped byte: the old quorum must not HIT. The HIT tickets
 * are made once per fixture; each field case reuses them. */
static int ptt_case_field(int f)
{
    int failures = 0;
    char name[128];
    snprintf(name, sizeof(name), "proof_ticket: one byte of %s -> MISS",
             vcs_component_proof_field_name((enum vcs_component_proof_field)f));
    TEST_CASE(name) {
        struct vcs_component_proof_key_v1 local = g_f.base;
        local.roots[f][31] ^= 0x01;
        ASSERT_EQ(vcs_component_proof_key_diff(&g_f.base, &local), 1u << f);
        struct vcs_proof_reuse_policy policy = g_f.policy;
        memcpy(policy.policy_root, local.roots[VCS_CPK_POLICY], 32);
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&local, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_NONE);
    } TEST_END
    return failures;
}

static int ptt_case_flag_order(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: swapping two flags is another action -> MISS") {
        ASSERT(ptt_fresh());
        const char *argv[3] = {"-O2", "-DNDEBUG", "-Wall"};
        const char *swapped[3] = {"-DNDEBUG", "-O2", "-Wall"};
        struct vcs_component_proof_key_v1 k = g_f.base, s = g_f.base;
        ASSERT(vcs_component_proof_ordered_root(VCS_CPK_FLAGS, argv, 3,
                                                k.roots[VCS_CPK_FLAGS]));
        ASSERT(vcs_component_proof_ordered_root(VCS_CPK_FLAGS, swapped, 3,
                                                s.roots[VCS_CPK_FLAGS]));
        ASSERT(ptt_emit_sync(&k, ptf_pass(), PTT_AB, 2));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&k, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT(ptt_decide(&s, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

static int ptt_case_uncheckpointed(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: uncheckpointed and forged tickets never count") {
        ASSERT(ptt_fresh());
        uint8_t wa[VCS_PROOF_TICKET_WIRE_BYTES], wb[sizeof(wa)];
        ASSERT(ptf_emit(&g_f, PTF_A, &g_f.base, ptf_pass(), wa, NULL));
        ASSERT(ptf_emit(&g_f, PTF_B, &g_f.base, ptf_pass(), wb, NULL));
        wb[300] ^= 0x40; /* forge B's signature */
        ASSERT(vcs_proof_receiver_add_ticket(g_f.rx, wa, sizeof(wa), NULL));
        ASSERT(vcs_proof_receiver_add_ticket(g_f.rx, wb, sizeof(wb), NULL));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_NOT_CHECKPOINTED);
        ASSERT_STR_EQ(cls[1].reason, VCS_PROOF_TICKET_SIGNATURE_INVALID);
        /* A relay that swaps in the forged bytes cannot extend coverage. */
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(vcs_proof_issuer_log_checkpoint(g_f.logs[PTF_B], 9, cp));
        const uint8_t *delta[1] = {wb};
        size_t lens[1] = {sizeof(wb)};
        struct vcs_proof_sync_report rep;
        ASSERT(vcs_proof_receiver_sync(g_f.rx, cp, sizeof(cp), delta, lens, 1,
                                       &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_REFUSED);
        ASSERT_STR_EQ(rep.reason, VCS_PROOF_SYNC_WHY_DELTA);
        ASSERT(!vcs_proof_receiver_issuer_equivocating(g_f.rx, g_f.pub[PTF_B]));
    } TEST_END
    return failures;
}

static int ptt_case_forged_ticket_under_signed_checkpoint(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: signed checkpoint cannot cover forged ticket") {
        ASSERT(ptt_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t root[32], checkpoint[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        ASSERT(ptf_emit(&g_f, PTF_A, &g_f.base, ptf_pass(), ticket, NULL));
        ticket[300] ^= 0x40; /* Keep the canonical body; break Ed25519. */
        ASSERT(vcs_proof_ticket_observation_root(ticket, sizeof(ticket), root));
        struct mmr log;
        mmr_init(&log);
        mmr_append(&log, root);
        struct vcs_proof_checkpoint_v1 cp = {0};
        cp.leaf_count = 1;
        cp.created_unix = 1790000001u;
        mmr_root(&log, cp.mmr_root);
        ASSERT(vcs_proof_checkpoint_peaks_root(&log, cp.peaks_root));
        ASSERT(vcs_proof_checkpoint_sign(&cp, g_f.seed[PTF_A]));
        ASSERT(vcs_proof_checkpoint_encode(&cp, checkpoint));
        ASSERT(vcs_proof_checkpoint_signature_valid(&cp));
        const uint8_t *delta[1] = {ticket};
        size_t lengths[1] = {sizeof(ticket)};
        struct vcs_proof_sync_report rep;
        ASSERT(vcs_proof_receiver_sync(g_f.rx, checkpoint, sizeof(checkpoint),
                                       delta, lengths, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_REFUSED);
        ASSERT_STR_EQ(rep.reason, VCS_PROOF_SYNC_WHY_DELTA);
        ASSERT_EQ(vcs_proof_receiver_issuer_leaves(g_f.rx, g_f.pub[PTF_A]),
                  (uint64_t)0);
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_f.rx, g_f.pub[PTF_A]),
                  (size_t)0);
    } TEST_END
    return failures;
}

static int ptt_case_forged_ticket_classification(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: classifier checks retained ticket signature") {
        ASSERT(ptt_fresh());
        uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
        ASSERT(ptf_emit(&g_f, PTF_A, &g_f.base, ptf_pass(), ticket, NULL));
        ticket[300] ^= 0x40;
        ASSERT(vcs_proof_receiver_add_ticket(g_f.rx, ticket, sizeof(ticket),
                                             NULL));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_EQ(d.tickets_seen, 1u);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_SIGNATURE_INVALID);
    } TEST_END
    return failures;
}

/* A signer in the candidate domain is refused even when listed trusted. */
static int ptt_case_domain_signer(int who, const char *label)
{
    int failures = 0;
    char name[128];
    snprintf(name, sizeof(name), "proof_ticket: %s signer refused for reuse",
             label);
    TEST_CASE(name) {
        ASSERT(ptt_fresh());
        uint8_t verifiers[4][32];
        memcpy(verifiers, g_f.verifiers, sizeof(verifiers));
        memcpy(verifiers[3], g_f.pub[who], 32);
        struct vcs_proof_reuse_policy policy = g_f.policy;
        policy.verifiers = (const uint8_t (*)[32])verifiers;
        policy.verifier_count = 4;
        policy.quorum = 1;
        int signers[1] = {who};
        ASSERT(ptt_emit_sync(&g_f.base, ptf_pass(), signers, 1));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_SIGNER_IN_DOMAIN);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

static int ptt_case_stranger(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: untrusted checkpointed signer is ineligible") {
        ASSERT(ptt_fresh());
        int signers[1] = {PTF_STRANGER};
        ASSERT(ptt_emit_sync(&g_f.base, ptf_pass(), signers, 1));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_SIGNER_UNTRUSTED);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

static int ptt_case_reused_basis(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: 3 REUSED tickets over 1 execution miss quorum 2") {
        ASSERT(ptt_fresh());
        uint8_t root[32];
        struct vcs_proof_sync_report rep;
        ASSERT(ptf_emit(&g_f, PTF_A, &g_f.base, ptf_pass(), NULL, root));
        struct ptf_spec reused = ptf_pass();
        reused.basis = VCS_PROOF_BASIS_REUSED;
        reused.basis_ref = root;
        for (int s = PTF_A; s <= PTF_C; s++)
            ASSERT(ptf_emit(&g_f, s, &g_f.base, reused, NULL, NULL));
        for (int s = PTF_A; s <= PTF_C; s++)
            ASSERT(ptf_sync(&g_f, s, 0, &rep));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.tickets_seen, 4u);
        ASSERT_EQ(d.distinct_pass_signers, 1u);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_STR_EQ(cls[3].reason, VCS_PROOF_TICKET_REUSED);
    } TEST_END
    return failures;
}

static int ptt_case_conflict(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: eligible PASS+FAIL refuses, all roots retained") {
        ASSERT(ptt_fresh());
        int fail[1] = {PTF_C};
        ASSERT(ptt_emit_sync(&g_f.base, ptf_pass(), PTT_AB, 2));
        ASSERT(ptt_emit_sync(&g_f.base, ptf_fail(), fail, 1));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT_EQ(d.used_count, 3u);
        ASSERT_EQ(vcs_proof_receiver_lookup(g_f.rx, d.input_key, NULL, 0),
                  (size_t)3);
    } TEST_END
    return failures;
}

static int ptt_case_known_fail(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: an eligible FAIL alone is HIT_FAIL") {
        ASSERT(ptt_fresh());
        int b[1] = {PTF_B};
        ASSERT(ptt_emit_sync(&g_f.base, ptf_fail(), b, 1));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_FAIL);
    } TEST_END
    return failures;
}

/* An issuer-signed ticket claiming the local key over another preimage or
 * another source identity. */
static int ptt_case_key_lies(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: ticket key/preimage/source must all match") {
        ASSERT(ptt_fresh());
        struct vcs_proof_ticket_v1 t[2];
        uint8_t w[VCS_PROOF_TICKET_WIRE_BYTES];
        struct vcs_component_proof_key_v1 other = g_f.base;
        other.roots[VCS_CPK_TARGET][0] ^= 0x80;
        for (int i = 0; i < 2; i++) {
            ASSERT(ptf_emit(&g_f, PTF_STRANGER, &g_f.base, ptf_pass(), w, NULL));
            ASSERT(vcs_proof_ticket_decode(w, sizeof(w), &t[i]));
        }
        ASSERT(vcs_component_proof_key_preimage_root(&other,
                                                     t[0].key_preimage_root));
        t[1].source_root[0] ^= 0x01;
        struct vcs_proof_issuer_log *log = g_f.logs[PTF_A];
        ASSERT(vcs_proof_issuer_log_append(log, &t[0], w));
        ASSERT(vcs_proof_issuer_log_append(log, &t[1], w));
        struct vcs_proof_sync_report rep;
        ASSERT(ptf_sync(&g_f, PTF_A, 0, &rep));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.tickets_seen, 2u);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_PREIMAGE_MISMATCH);
        ASSERT_STR_EQ(cls[1].reason, VCS_PROOF_TICKET_SOURCE_MISMATCH);
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
    } TEST_END
    return failures;
}

static int ptt_case_policy(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: policy change MISS; inconsistent policy refused") {
        ASSERT(ptt_fresh());
        ASSERT(ptt_emit_sync(&g_f.base, ptf_pass(), PTT_AB, 2));
        struct vcs_component_proof_key_v1 local = g_f.base;
        ptf_root(VCS_CPK_POLICY, "policy-v2", local.roots[VCS_CPK_POLICY]);
        struct vcs_proof_reuse_policy policy = g_f.policy;
        memcpy(policy.policy_root, local.roots[VCS_CPK_POLICY], 32);
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&local, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT(!ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_POLICY_ROOT);
        policy = g_f.policy;
        policy.quorum = 0;
        ASSERT(!ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_POLICY);
    } TEST_END
    return failures;
}

static int ptt_case_one_signer_twice(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: quorum 2 with one signer twice is not HIT") {
        ASSERT(ptt_fresh());
        struct ptf_spec later = ptf_pass();
        later.created = 1790000100u;
        int a[1] = {PTF_A};
        ASSERT(ptt_emit_sync(&g_f.base, ptf_pass(), a, 1));
        ASSERT(ptt_emit_sync(&g_f.base, later, a, 1));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_EQ(d.distinct_pass_signers, 1u);
    } TEST_END
    return failures;
}

static int ptt_case_freshness(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: stale and future tickets ineligible") {
        ASSERT(ptt_fresh());
        struct ptf_spec old = ptf_pass(), future = ptf_pass();
        old.created = 1000;
        future.created = 1790009999u;
        int a[1] = {PTF_A}, b[1] = {PTF_B};
        ASSERT(ptt_emit_sync(&g_f.base, old, a, 1));
        ASSERT(ptt_emit_sync(&g_f.base, future, b, 1));
        struct vcs_proof_reuse_policy policy = g_f.policy;
        policy.now_unix = 1790000000u;
        policy.max_age_seconds = 86400u;
        policy.max_future_seconds = 300u;
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_STR_EQ(ptt_reason_of(cls, d.tickets_seen, PTF_A),
                      VCS_PROOF_TICKET_STALE);
        ASSERT_STR_EQ(ptt_reason_of(cls, d.tickets_seen, PTF_B),
                      VCS_PROOF_TICKET_FUTURE);
    } TEST_END
    return failures;
}

static int ptt_case_revocation(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: revoking a verifier after ingest takes effect") {
        ASSERT(ptt_fresh());
        ASSERT(ptt_emit_sync(&g_f.base, ptf_pass(), PTT_AB, 2));
        struct vcs_proof_ticket_class cls[PTT_CLASS_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, NULL, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        struct vcs_proof_reuse_policy policy = g_f.policy;
        uint8_t revoked[1][32];
        memcpy(revoked[0], g_f.pub[PTF_B], 32);
        policy.revoked = (const uint8_t (*)[32])revoked;
        policy.revoked_count = 1;
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(ptt_reason_of(cls, d.tickets_seen, PTF_B),
                      VCS_PROOF_TICKET_SIGNER_REVOKED);
        policy = g_f.policy;
        policy.verifier_count = 1; /* B dropped from the set */
        ASSERT(ptt_decide(&g_f.base, VCS_PROOF_ACTION_CHECK, &policy, cls, &d));
        ASSERT_STR_EQ(ptt_reason_of(cls, d.tickets_seen, PTF_B),
                      VCS_PROOF_TICKET_SIGNER_UNTRUSTED);
    } TEST_END
    return failures;
}

int test_proof_ticket_reuse(void);


int test_proof_ticket_reuse(void)
{
    int failures = 0;
    failures += ptt_case_roundtrip();
    failures += ptt_case_ticket_refusals();
    failures += ptt_case_other_refusals();
    failures += ptt_case_field_helpers();
    failures += ptt_case_contract();
    failures += ptt_case_baseline_hit();
    for (int f = 0; f < VCS_CPK_FIELD_COUNT; f++)
        failures += ptt_case_field(f);
    failures += ptt_case_flag_order();
    failures += ptt_case_uncheckpointed();
    failures += ptt_case_forged_ticket_under_signed_checkpoint();
    failures += ptt_case_forged_ticket_classification();
    failures += ptt_case_domain_signer(PTF_AUTHOR, "candidate author");
    failures += ptt_case_domain_signer(PTF_LOCAL, "same-uid local proof");
    failures += ptt_case_domain_signer(PTF_EXTRA, "candidate-domain extra");
    failures += ptt_case_stranger();
    failures += ptt_case_reused_basis();
    failures += ptt_case_conflict();
    failures += ptt_case_known_fail();
    failures += ptt_case_key_lies();
    failures += ptt_case_policy();
    failures += ptt_case_one_signer_twice();
    failures += ptt_case_freshness();
    failures += ptt_case_revocation();
    failures += ptf_log_cases();
    ptf_free(&g_f);
    return failures;
}
