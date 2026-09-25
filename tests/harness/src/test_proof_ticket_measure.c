/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic reuse measurement over issuer checkpoints.
 *
 * Measurement: 6 candidates (one cold baseline, then candidates changing
 * 1-10% of 200 obligations plus one shared header edit) against three
 * independent issuers with their own signed logs. The candidate author and
 * the same-uid local signer "prove" everything they touch, one issuer
 * signs REUSED provenance for hits, one artifact is tampered in the CAS and
 * one issuer contradicts an honest PASS. Prints one parseable line and
 * requires zero false hits and >95% reuse of unchanged obligations. */

#include "test/test_core.h"

#include "test/proof_ticket_fixture.h"

#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PTM_UNITS 200u
#define PTM_CANDIDATES 6u
#define PTM_HEADER_UNITS 60u
#define PTM_FLAKY_UNIT 17u
#define PTM_BROKEN_UNIT 42u
#define PTM_TAMPER_UNIT 101u
#define PTM_CAP 64u

enum { PTM_WHY_DOMAIN = 0, PTM_WHY_REUSED, PTM_WHY_UNCOVERED, PTM_WHY_OTHER,
       PTM_WHY_ARTIFACT, PTM_WHY_COUNT };

static const char *const ptm_why_names[PTM_WHY_COUNT] = {
    "signer_in_candidate_domain", "reused_not_independent",
    "not_checkpointed", "other_ineligible", "artifact_bytes_mismatch",
};

struct ptm {
    struct ptf f;
    uint32_t version[PTM_UNITS];
    uint32_t header;
    uint64_t rng;
    uint32_t candidate;
    uint32_t turn;
    bool changed[PTM_UNITS];
    uint64_t obligations, eligible_proofs, reused, fresh, refused;
    uint64_t unchanged, unchanged_reused;
    uint64_t false_hits, why[PTM_WHY_COUNT];
    uint64_t tickets_classified, decide_us, full_log_bytes;
};

static uint32_t ptm_rand(struct ptm *s)
{
    s->rng = s->rng * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(s->rng >> 33);
}

static enum vcs_proof_action_class ptm_class(uint32_t u)
{
    return u % 4u == 0 ? VCS_PROOF_ACTION_CHECK : VCS_PROOF_ACTION_BUILD;
}

static bool ptm_truly_passes(const struct ptm *s, uint32_t u)
{
    return !(u == PTM_BROKEN_UNIT && (s->version[u] & 1u));
}

static void ptm_key(const struct ptm *s, uint32_t u,
                    struct vcs_component_proof_key_v1 *k)
{
    char text[96];
    *k = s->f.base;
    snprintf(text, sizeof(text), "unit/%u", u);
    ptf_root(VCS_CPK_UNIT_ID, text, k->roots[VCS_CPK_UNIT_ID]);
    snprintf(text, sizeof(text), "src/%u@%u", u, s->version[u]);
    ptf_root(VCS_CPK_SOURCE_CLOSURE, text, k->roots[VCS_CPK_SOURCE_CLOSURE]);
    ptf_root(VCS_CPK_KIND, ptm_class(u) == VCS_PROOF_ACTION_BUILD ?
                               "compile" : "test",
             k->roots[VCS_CPK_KIND]);
    if (u < PTM_HEADER_UNITS) {
        snprintf(text, sizeof(text), "shared.h@%u", s->header);
        ptf_root(VCS_CPK_DEPENDENCY_CLOSURE, text,
                 k->roots[VCS_CPK_DEPENDENCY_CLOSURE]);
    }
}

static struct ptf_spec ptm_spec(struct ptm *s, uint32_t u, bool pass)
{
    struct ptf_spec spec = pass ? ptf_pass() : ptf_fail();
    spec.action_class = ptm_class(u);
    spec.created = 1790000000u + s->candidate;
    return spec;
}

/* Two of three issuers execute the obligation independently. */
static bool ptm_execute(struct ptm *s, uint32_t u,
                        const struct vcs_component_proof_key_v1 *k)
{
    for (int i = 0; i < 2; i++) {
        int issuer = (int)(s->turn++ % 3u);
        if (!ptf_emit(&s->f, issuer, k, ptm_spec(s, u, ptm_truly_passes(s, u)),
                      NULL, NULL))
            return false;
    }
    return true;
}

static void ptm_audit(struct ptm *s, uint32_t u,
                      const struct vcs_proof_ticket_class *cls,
                      const struct vcs_proof_reuse_decision *d)
{
    s->tickets_classified += d->tickets_seen;
    for (uint32_t i = 0; i < d->tickets_seen; i++) {
        const char *why = cls[i].reason;
        if (cls[i].eligible) { s->eligible_proofs++; continue; }
        if (strcmp(why, VCS_PROOF_TICKET_SIGNER_IN_DOMAIN) == 0)
            s->why[PTM_WHY_DOMAIN]++;
        else if (strcmp(why, VCS_PROOF_TICKET_REUSED) == 0)
            s->why[PTM_WHY_REUSED]++;
        else if (strcmp(why, VCS_PROOF_TICKET_NOT_CHECKPOINTED) == 0)
            s->why[PTM_WHY_UNCOVERED]++;
        else
            s->why[PTM_WHY_OTHER]++;
    }
    if (d->false_hit_refused) s->why[PTM_WHY_ARTIFACT]++;
    if (d->outcome == VCS_PROOF_REUSE_HIT_PASS &&
        (!ptm_truly_passes(s, u) || d->distinct_pass_signers < 2))
        s->false_hits++;
}

/* On a hit, issuer C records that it reused the observation: provenance
 * that must never count toward a quorum. */
static bool ptm_provenance(struct ptm *s, uint32_t u,
                           const struct vcs_component_proof_key_v1 *k,
                           const struct vcs_proof_reuse_decision *d)
{
    if (u % 10u != 0 || d->used_count == 0) return true;
    struct ptf_spec spec = ptm_spec(s, u, true);
    spec.basis = VCS_PROOF_BASIS_REUSED;
    spec.basis_ref = d->used[0];
    return ptf_emit(&s->f, PTF_C, k, spec, NULL, NULL);
}

static bool ptm_account(struct ptm *s, uint32_t u,
                        const struct vcs_component_proof_key_v1 *k,
                        const struct vcs_proof_reuse_decision *d)
{
    bool reused = d->outcome == VCS_PROOF_REUSE_HIT_PASS ||
                  d->outcome == VCS_PROOF_REUSE_HIT_FAIL;
    bool unchanged = s->candidate > 0 && !s->changed[u] &&
                     !(s->candidate == 3 && u < PTM_HEADER_UNITS);
    s->unchanged += unchanged ? 1u : 0u;
    s->unchanged_reused += unchanged && reused ? 1u : 0u;
    if (d->outcome == VCS_PROOF_REUSE_REFUSE) s->refused++;
    if (reused) {
        s->reused++;
        return d->outcome != VCS_PROOF_REUSE_HIT_PASS ||
               ptm_provenance(s, u, k, d);
    }
    s->fresh++;
    return ptm_execute(s, u, k);
}

static bool ptm_obligation(struct ptm *s, uint32_t u)
{
    struct vcs_component_proof_key_v1 k;
    ptm_key(s, u, &k);
    struct vcs_proof_ticket_class cls[PTM_CAP];
    struct vcs_proof_reuse_decision d;
    s->f.tamper = s->candidate == 3 && u == PTM_TAMPER_UNIT;
    int64_t t0 = platform_time_monotonic_us();
    bool ok = ptf_decide(&s->f, &k, ptm_class(u), NULL, cls, PTM_CAP, &d);
    s->decide_us += (uint64_t)(platform_time_monotonic_us() - t0);
    if (s->f.tamper && d.outcome == VCS_PROOF_REUSE_HIT_PASS) ok = false;
    s->f.tamper = false;
    if (!ok) return false;
    s->obligations++;
    ptm_audit(s, u, cls, &d);
    return ptm_account(s, u, &k, &d);
}

/* Candidate-domain keys "prove" what the candidate touched. */
static bool ptm_attack(struct ptm *s, uint32_t u)
{
    struct vcs_component_proof_key_v1 k;
    ptm_key(s, u, &k);
    return ptf_emit(&s->f, PTF_AUTHOR, &k, ptm_spec(s, u, true), NULL, NULL) &&
           ptf_emit(&s->f, PTF_LOCAL, &k, ptm_spec(s, u, true), NULL, NULL);
}

static bool ptm_sync_all(struct ptm *s)
{
    static const int who[5] = {PTF_A, PTF_B, PTF_C, PTF_AUTHOR, PTF_LOCAL};
    bool ok = true;
    for (int i = 0; i < 5 && ok; i++) {
        struct vcs_proof_sync_report rep;
        uint64_t n = vcs_proof_issuer_log_count(s->f.logs[who[i]]);
        if (n == vcs_proof_receiver_issuer_leaves(s->f.rx, s->f.pub[who[i]]))
            continue;
        s->full_log_bytes += VCS_PROOF_CHECKPOINT_WIRE_BYTES +
                             n * VCS_PROOF_TICKET_WIRE_BYTES;
        ok = ptf_sync(&s->f, who[i], 1790000001u + s->candidate, &rep) &&
             rep.outcome == VCS_PROOF_SYNC_ADVANCED;
    }
    return ok;
}

/* The flaky issuer C reports FAIL for an obligation that truly passes. */
static bool ptm_contradict(struct ptm *s)
{
    struct vcs_component_proof_key_v1 k;
    ptm_key(s, PTM_FLAKY_UNIT, &k);
    return ptf_emit(&s->f, PTF_C, &k, ptm_spec(s, PTM_FLAKY_UNIT, false),
                    NULL, NULL);
}

static bool ptm_change(struct ptm *s)
{
    static const uint32_t per_mille[PTM_CANDIDATES] = {0, 10, 30, 50, 70, 100};
    memset(s->changed, 0, sizeof(s->changed));
    if (s->candidate == 3) s->header++; /* one shared header edit */
    uint32_t n = PTM_UNITS * per_mille[s->candidate] / 1000u;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t u = ptm_rand(s) % PTM_UNITS;
        if (u == PTM_TAMPER_UNIT || u == PTM_FLAKY_UNIT) continue;
        s->version[u]++;
        s->changed[u] = true;
        if (!ptm_attack(s, u)) return false;
    }
    if (s->candidate == 2 && (s->version[PTM_BROKEN_UNIT] & 1u) == 0) {
        s->version[PTM_BROKEN_UNIT]++;
        s->changed[PTM_BROKEN_UNIT] = true;
    }
    return true;
}

static bool ptm_candidate(struct ptm *s)
{
    if (!ptm_change(s)) return false;
    if (s->candidate == 4 && !ptm_contradict(s)) return false;
    if (!ptm_sync_all(s)) return false;
    for (uint32_t u = 0; u < PTM_UNITS; u++)
        if (!ptm_obligation(s, u)) return false;
    return ptm_sync_all(s);
}

static void ptm_print(const struct ptm *s)
{
    uint64_t cps = s->f.sync_checkpoints ? s->f.sync_checkpoints : 1u;
    uint64_t seen = s->tickets_classified ? s->tickets_classified : 1u;
    printf("\nproof_ticket_reuse_measure candidates=%u issuers=3 "
           "obligations_per_candidate=%u obligations=%llu eligible_proofs=%llu "
           "reused_proofs=%llu fresh_proofs=%llu refused=%llu "
           "unchanged=%llu reuse_rate_unchanged_pct=%.2f "
           "verify_cpu_us_total=%llu verify_us_per_ticket=%.2f "
           "verify_us_per_checkpoint=%.1f bytes_synced=%llu "
           "bytes_full_logs=%llu false_hit_refusals=",
           PTM_CANDIDATES, PTM_UNITS, (unsigned long long)s->obligations,
           (unsigned long long)s->eligible_proofs,
           (unsigned long long)s->reused, (unsigned long long)s->fresh,
           (unsigned long long)s->refused, (unsigned long long)s->unchanged,
           s->unchanged ? 100.0 * (double)s->unchanged_reused /
                              (double)s->unchanged : 0.0,
           (unsigned long long)(s->decide_us + s->f.sync_verify_us),
           (double)s->decide_us / (double)seen,
           (double)s->f.sync_verify_us / (double)cps,
           (unsigned long long)s->f.sync_bytes,
           (unsigned long long)s->full_log_bytes);
    for (int i = 0; i < PTM_WHY_COUNT; i++)
        printf("%s%s:%llu", i ? "," : "", ptm_why_names[i],
               (unsigned long long)s->why[i]);
    printf(" false_hits=%llu\n", (unsigned long long)s->false_hits);
}

static int ptm_case_measure(void)
{
    int failures = 0;
    TEST_CASE("proof_ticket: 6 candidates x 3 issuers x 200 obligations") {
        struct ptm *s = calloc(1, sizeof(*s));
        ASSERT(s != NULL);
        bool ok = ptf_init(&s->f);
        s->rng = 0x5eed1234abcdull;
        for (s->candidate = 0; ok && s->candidate < PTM_CANDIDATES;
             s->candidate++)
            ok = ptm_candidate(s);
        ptm_print(s);
        struct ptm r = *s;
        ptf_free(&s->f);
        free(s);
        ASSERT(ok);
        ASSERT_EQ(r.obligations, (uint64_t)PTM_UNITS * PTM_CANDIDATES);
        ASSERT_EQ(r.false_hits, 0u);
        ASSERT(r.why[PTM_WHY_ARTIFACT] == 1u);   /* the tampered artifact */
        ASSERT(r.why[PTM_WHY_DOMAIN] > 0u);      /* attacks were seen */
        ASSERT(r.why[PTM_WHY_REUSED] > 0u);      /* provenance never counts */
        ASSERT(r.refused >= 1u);                  /* the contradiction */
        ASSERT(r.unchanged_reused * 100u > r.unchanged * 95u);
        ASSERT(r.f.sync_bytes < r.full_log_bytes);
    } TEST_END
    return failures;
}

int test_proof_ticket_measure(void);

int test_proof_ticket_measure(void)
{
    int failures = 0;
    failures += ptm_case_measure();
    return failures;
}
