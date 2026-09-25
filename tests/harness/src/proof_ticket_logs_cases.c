/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Issuer-log, equivocation, artifact-verification and CAS rebuild
 *          cases for the proof_ticket_reuse group. */

#include "test/test_core.h"

#include "test/proof_ticket_fixture.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <string.h>

static struct ptf g_l;

#define PTL_CAP 16u

static bool ptl_fresh(void)
{
    ptf_free(&g_l);
    return ptf_init(&g_l);
}

static bool ptl_sync_wires(const uint8_t *cp, const uint8_t *const *delta,
                           size_t n, struct vcs_proof_sync_report *rep)
{
    size_t lens[8];
    for (size_t i = 0; i < n && i < 8; i++)
        lens[i] = VCS_PROOF_TICKET_WIRE_BYTES;
    return vcs_proof_receiver_sync(g_l.rx, cp, VCS_PROOF_CHECKPOINT_WIRE_BYTES,
                                   delta, lens, n, rep);
}

/* A forked log with A's own key: the same issuer signing a second history. */
static struct vcs_proof_issuer_log *ptl_fork(void)
{
    return vcs_proof_issuer_log_new(g_l.seed[PTF_A]);
}

static bool ptl_append(struct vcs_proof_issuer_log *log, struct ptf_spec s,
                       uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES])
{
    struct vcs_proof_ticket_v1 t;
    uint8_t tmp[VCS_PROOF_TICKET_WIRE_BYTES];
    /* Borrow the fixture's canonical fill through a throwaway emit. */
    if (!ptf_emit(&g_l, PTF_STRANGER, &g_l.base, s, tmp, NULL) ||
        !vcs_proof_ticket_decode(tmp, sizeof(tmp), &t))
        return false;
    return vcs_proof_issuer_log_append(log, &t, wire);
}

static int ptl_case_same_count(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: two signed roots at one size -> equivocation") {
        ASSERT(ptl_fresh());
        struct vcs_proof_sync_report rep;
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_emit(&g_l, PTF_B, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT(ptf_sync(&g_l, PTF_B, 0, &rep));
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        uint8_t w[VCS_PROOF_TICKET_WIRE_BYTES], cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        bool ok = ptl_append(fork, ptf_fail(), w) &&
                  vcs_proof_issuer_log_checkpoint(fork, 5, cp);
        vcs_proof_issuer_log_free(fork);
        ASSERT(ok);
        ASSERT(ptl_sync_wires(cp, NULL, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
        ASSERT(vcs_proof_receiver_issuer_equivocating(g_l.rx, g_l.pub[PTF_A]));
        ASSERT_EQ(vcs_proof_receiver_issuer_checkpoints(g_l.rx, g_l.pub[PTF_A]),
                  (size_t)2); /* both sides kept */
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_EQUIVOCATION);
    } TEST_END
    return failures;
}

static int ptl_case_fork(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: second child of one checkpoint -> equivocation") {
        ASSERT(ptl_fresh());
        struct vcs_proof_sync_report rep;
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        /* A fork whose first checkpoint names no predecessor, at 3 leaves:
         * it claims the same parent as the receiver's first checkpoint. */
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        uint8_t w[3][VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        bool ok = true;
        for (int i = 0; i < 3 && ok; i++) ok = ptl_append(fork, ptf_pass(), w[i]);
        ok = ok && vcs_proof_issuer_log_checkpoint(fork, 5, cp);
        vcs_proof_issuer_log_free(fork);
        ASSERT(ok);
        const uint8_t *delta[1] = {w[2]};
        ASSERT(ptl_sync_wires(cp, delta, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
    } TEST_END
    return failures;
}

static int ptl_case_not_extension(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: signed delta that misses the root -> equivocation") {
        ASSERT(ptl_fresh());
        struct vcs_proof_issuer_log *fork = ptl_fork();
        ASSERT(fork != NULL);
        uint8_t w0[VCS_PROOF_TICKET_WIRE_BYTES], w1[sizeof(w0)], f1[sizeof(w0)];
        uint8_t cp1[VCS_PROOF_CHECKPOINT_WIRE_BYTES], cpf[sizeof(cp1)];
        uint8_t fcp1[sizeof(cp1)];
        struct vcs_proof_ticket_v1 t;
        struct ptf_spec later = ptf_pass();
        later.created = 1790000500u;
        bool ok = ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), w0, NULL) &&
                  vcs_proof_ticket_decode(w0, sizeof(w0), &t) &&
                  vcs_proof_issuer_log_append(fork, &t, w0) &&
                  vcs_proof_issuer_log_checkpoint(g_l.logs[PTF_A], 5, cp1) &&
                  vcs_proof_issuer_log_checkpoint(fork, 5, fcp1) &&
                  ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), w1, NULL) &&
                  ptl_append(fork, later, f1) &&
                  vcs_proof_issuer_log_checkpoint(fork, 6, cpf);
        vcs_proof_issuer_log_free(fork);
        ASSERT(ok);
        ASSERT(memcmp(cp1, fcp1, sizeof(cp1)) == 0); /* one shared prefix */
        struct vcs_proof_sync_report rep;
        const uint8_t *d0[1] = {w0}, *d1[1] = {w1};
        ASSERT(ptl_sync_wires(cp1, d0, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        /* The fork's checkpoint plus A's genuinely signed seq-1 ticket. */
        ASSERT(ptl_sync_wires(cpf, d1, 1, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_EQUIVOCATION);
    } TEST_END
    return failures;
}

static int ptl_case_delta_bytes(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: a resync moves only the new tickets") {
        ASSERT(ptl_fresh());
        struct vcs_proof_sync_report rep;
        for (int i = 0; i < 5; i++)
            ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT_EQ(rep.bytes, (uint64_t)(VCS_PROOF_CHECKPOINT_WIRE_BYTES +
                                        5u * VCS_PROOF_TICKET_WIRE_BYTES));
        ASSERT(ptf_emit(&g_l, PTF_A, &g_l.base, ptf_pass(), NULL, NULL));
        ASSERT(ptf_sync(&g_l, PTF_A, 0, &rep));
        ASSERT_EQ(rep.outcome, VCS_PROOF_SYNC_ADVANCED);
        ASSERT_EQ(rep.leaves_before, (uint64_t)5);
        ASSERT_EQ(rep.bytes, (uint64_t)(VCS_PROOF_CHECKPOINT_WIRE_BYTES +
                                        VCS_PROOF_TICKET_WIRE_BYTES));
    } TEST_END
    return failures;
}

static struct ptf_spec ptl_build(uint8_t salt)
{
    struct ptf_spec s = ptf_pass();
    s.action_class = VCS_PROOF_ACTION_BUILD;
    s.artifact_salt = salt;
    return s;
}

static bool ptl_build_quorum(uint8_t salt_b)
{
    struct vcs_proof_sync_report rep;
    return ptf_emit(&g_l, PTF_A, &g_l.base, ptl_build(0), NULL, NULL) &&
           ptf_emit(&g_l, PTF_B, &g_l.base, ptl_build(salt_b), NULL, NULL) &&
           ptf_sync(&g_l, PTF_A, 0, &rep) && ptf_sync(&g_l, PTF_B, 0, &rep);
}

static int ptl_case_artifact(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: build reuse re-hashes the artifact bytes") {
        ASSERT(ptl_fresh());
        ASSERT(ptl_build_quorum(0));
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT(memcmp(d.artifact_root, cls[0].artifact_root, 32) == 0);
        g_l.tamper = true;
        memcpy(g_l.tamper_root, d.artifact_root, 32);
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_MISS);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_ARTIFACT_MISMATCH);
        ASSERT(d.false_hit_refused);
        g_l.tamper = false;
        size_t held = g_l.art_count;
        g_l.art_count = 0; /* the bytes are absent from the CAS */
        bool decided = ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD,
                                  NULL, cls, PTL_CAP, &d);
        g_l.art_count = held;
        ASSERT(decided);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_ARTIFACT_MISSING);
        /* The same obligation asked as a CHECK is another action class. */
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_STR_EQ(cls[0].reason, VCS_PROOF_TICKET_CLASS_MISMATCH);
    } TEST_END
    return failures;
}

static int ptl_case_output_conflict(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: two outputs for one build action -> conflict") {
        ASSERT(ptl_fresh());
        ASSERT(ptl_build_quorum(0x55));
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_BUILD, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
    } TEST_END
    return failures;
}

static bool ptl_store_logs(struct vcs_package_store *store)
{
    uint8_t root[32], pre[VCS_CPK_WIRE_BYTES];
    uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    if (!vcs_component_proof_key_encode(&g_l.base, pre) ||
        !vcs_proof_ticket_store_put(store, pre, sizeof(pre), root))
        return false;
    for (int s = PTF_A; s <= PTF_B; s++) {
        struct vcs_proof_issuer_log *log = g_l.logs[s];
        for (uint64_t i = 0; i < vcs_proof_issuer_log_count(log); i++)
            if (!vcs_proof_ticket_store_put(store,
                                            vcs_proof_issuer_log_ticket(log, i),
                                            VCS_PROOF_TICKET_WIRE_BYTES, root))
                return false;
        if (!vcs_proof_issuer_log_checkpoint(log, 9, cp) ||
            !vcs_proof_ticket_store_put(store, cp, sizeof(cp), root))
            return false;
    }
    return true;
}

static int ptl_case_rebuild(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: receiver rebuilt from CAS blobs reaches HIT") {
        ASSERT(ptl_fresh());
        for (int s = PTF_A; s <= PTF_B; s++)
            ASSERT(ptf_emit(&g_l, s, &g_l.base, ptf_pass(), NULL, NULL));
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "proof_ticket", "cas");
        struct vcs_package_store *store =
            vcs_package_store_open(dir, UINT64_C(8) * 1024 * 1024);
        ASSERT(store != NULL);
        size_t tickets = 0, cps = 0, skipped = 0;
        bool ok = ptl_store_logs(store) &&
                  vcs_proof_receiver_rebuild(g_l.rx, store, &tickets, &cps,
                                             &skipped);
        vcs_package_store_close(store);
        test_rm_rf(dir);
        ASSERT(ok);
        ASSERT_EQ(tickets, (size_t)2);
        ASSERT_EQ(cps, (size_t)2);
        ASSERT_EQ(skipped, (size_t)1); /* the key preimage */
        struct vcs_proof_ticket_class cls[PTL_CAP];
        struct vcs_proof_reuse_decision d;
        ASSERT(ptf_decide(&g_l, &g_l.base, VCS_PROOF_ACTION_CHECK, NULL, cls,
                          PTL_CAP, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
    } TEST_END
    return failures;
}

int ptf_log_cases(void)
{
    int failures = 0;
    failures += ptl_case_same_count();
    failures += ptl_case_fork();
    failures += ptl_case_not_extension();
    failures += ptl_case_delta_bytes();
    failures += ptl_case_artifact();
    failures += ptl_case_output_conflict();
    failures += ptl_case_rebuild();
    ptf_free(&g_l);
    return failures;
}
