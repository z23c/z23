/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The queued CHECK dimension derives its closure and asks admission
 *          before any test child. Launch counts come from the forked step,
 *          not from a flag the decider writes for itself. Missing issuer
 *          history is a package-store rebuild after compaction, and that
 *          MISS still forks the test child. */

#include "test/test_core.h"

#include "test/proof_ticket_fixture.h"

#include "dev_proof.h"
#include "dev_proof_signer.h"
#include "platform/time_compat.h"
#include "verify_attest.h"
#include "verify_receiver.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

enum { SEAM_RAW = 9, SEAM_CLASS = 8, SEAM_PATH = 512 };

struct seam_meter {
    struct zcl_dev_proof_check_result out;
    int64_t wall_us;
    int64_t cpu_us;
};

static int64_t seam_cpu_us(const struct rusage *before, const struct rusage *after)
{
    int64_t user = (int64_t)(after->ru_utime.tv_sec - before->ru_utime.tv_sec) *
                       1000000 +
                   ((int64_t)after->ru_utime.tv_usec - before->ru_utime.tv_usec);
    int64_t sys = (int64_t)(after->ru_stime.tv_sec - before->ru_stime.tv_sec) *
                      1000000 +
                  ((int64_t)after->ru_stime.tv_usec - before->ru_stime.tv_usec);
    return user + sys;
}

static void seam_fill(uint8_t raw[SEAM_RAW][32],
                      struct zcl_dev_proof_check_inputs *in)
{
    memset(in, 0, sizeof(*in));
    for (int i = 0; i < SEAM_RAW; i++) {
        memset(raw[i], (unsigned char)(0x31 + i), 32);
        raw[i][0] = (unsigned char)(0xA0 + i);
    }
    in->unit = "proof-check-group";
    in->source_cas = raw[0];
    in->dependency = raw[1];
    in->harness = raw[2];
    in->flags = raw[3];
    in->environment = raw[4];
    in->build_graph = raw[5];
    in->toolchain = raw[6];
    in->policy = raw[7];
    in->changed = raw[8];
}

static bool seam_script(const char *path, unsigned ran)
{
    FILE *f = fopen(path, "w");
    int n;
    if (!f) return false;
    n = fprintf(f,
                "#!/bin/sh\n"
                "dd if=/dev/zero bs=1048576 count=64 2>/dev/null | "
                "sha256sum >/dev/null || exit 1\n"
                "printf '%%s\\n' 'SUITE VERDICT mode=cold groups_total=%u "
                "groups_ran=%u groups_cached=0 groups_gated=0 "
                "groups_failed=0 self_skips=0 env_unobserved=0'\n",
                ran, ran);
    if (n < 0 || fclose(f) != 0) return false;
    return chmod(path, 0700) == 0;
}

static bool seam_dir(char *dir, size_t cap, char *binary, size_t binary_cap,
                     unsigned ran)
{
    char *made = test_mkdtemp(dir, cap, "z23-check-seam");
    if (!made) return false;
    if (snprintf(binary, binary_cap, "%s/child.sh", dir) >= (int)binary_cap)
        return false;
    return seam_script(binary, ran);
}

static bool seam_align(struct ptf *f, const struct zcl_dev_proof_check_inputs *in,
                       struct vcs_component_proof_key_v1 *key,
                       struct vcs_proof_reuse_policy *policy)
{
    if (!zcl_dev_proof_check_closure_derive(in, key)) return false;
    *policy = f->policy;
    memcpy(policy->policy_root, key->roots[VCS_CPK_POLICY], 32);
    return true;
}

static bool seam_pass_sync(struct ptf *f, int signer,
                           const struct vcs_component_proof_key_v1 *key,
                           struct ptf_spec spec)
{
    struct vcs_proof_sync_report rep;
    if (!ptf_emit(f, signer, key, spec, NULL, NULL)) return false;
    if (!ptf_sync(f, signer, 0, &rep)) return false;
    return rep.outcome == VCS_PROOF_SYNC_ADVANCED;
}

static bool seam_quorum(struct ptf *f, const struct vcs_component_proof_key_v1 *key)
{
    return seam_pass_sync(f, PTF_A, key, ptf_pass()) &&
           seam_pass_sync(f, PTF_B, key, ptf_pass());
}

/* used[0] is nonzero. Local so the assertion text stays specific. */
static bool proof_root_used(const struct vcs_proof_reuse_decision *d)
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= d->used[0][i];
    return any != 0;
}

static bool seam_run(const struct zcl_dev_proof_check_inputs *in,
                     const char *dir, const char *binary, uint32_t selected,
                     const struct vcs_proof_receiver *rx,
                     const struct vcs_proof_candidate_domain *domain,
                     const struct vcs_proof_reuse_policy *policy,
                     struct seam_meter *meter)
{
    struct rusage before, after;
    int64_t began;
    if (getrusage(RUSAGE_CHILDREN, &before) != 0) return false;
    began = platform_time_monotonic_us();
    if (!zcl_dev_proof_check_dimensions(in, dir, dir, binary, selected, rx,
                                        domain, policy, &meter->out))
        return false;
    meter->wall_us = platform_time_monotonic_us() - began;
    if (getrusage(RUSAGE_CHILDREN, &after) != 0) return false;
    meter->cpu_us = seam_cpu_us(&before, &after);
    return true;
}

static int seam_case_hit_cold(void)
{
    int failures = 0;
    TEST_CASE("check seam: qualified hit launches no child; cold executes") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct vcs_proof_ticket_class cls[SEAM_CLASS];
        struct vcs_proof_reuse_decision decision;
        struct seam_meter hit, cold;
        char hit_dir[SEAM_PATH], cold_dir[SEAM_PATH], hit_bin[SEAM_PATH],
            cold_bin[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_quorum(&f, &key));
        ASSERT(seam_dir(hit_dir, sizeof(hit_dir), hit_bin, sizeof(hit_bin), 1));
        ASSERT(seam_dir(cold_dir, sizeof(cold_dir), cold_bin, sizeof(cold_bin), 1));
        ASSERT(seam_run(&in, hit_dir, hit_bin, 1, f.rx, &f.domain, &policy, &hit));
        ASSERT(seam_run(&in, cold_dir, cold_bin, 1, NULL, NULL, NULL, &cold));
        ASSERT(ptf_decide(&f, &key, VCS_PROOF_ACTION_CHECK, &policy, cls,
                          SEAM_CLASS, &decision));
        ASSERT_EQ(decision.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT(decision.used_count >= 1u);
        ASSERT(proof_root_used(&decision));
        ASSERT(memcmp(hit.out.receipt_root, decision.used[0], 32) == 0);
        ASSERT(hit.out.ok);
        ASSERT_EQ(hit.out.test_children, 0u);
        ASSERT_EQ(hit.out.reused, 1u);
        ASSERT_EQ(hit.out.ran, 0u);
        ASSERT(!hit.out.log_present);
        ASSERT(cold.out.ok);
        ASSERT_EQ(cold.out.test_children, 1u);
        ASSERT_EQ(cold.out.reused, 0u);
        ASSERT_EQ(cold.out.ran, 1u);
        ASSERT(cold.out.log_present);
        ASSERT(cold.out.test_children > hit.out.test_children);
        ASSERT(cold.wall_us > hit.wall_us);
        ASSERT(cold.cpu_us > hit.cpu_us);
        printf("check_seam hit_children=%u hit_reused=%u hit_wall_us=%lld "
               "hit_child_cpu_us=%lld cold_children=%u cold_reused=%u "
               "cold_wall_us=%lld cold_child_cpu_us=%lld observation_bound=1\n",
               hit.out.test_children, hit.out.reused, (long long)hit.wall_us,
               (long long)hit.cpu_us, cold.out.test_children, cold.out.reused,
               (long long)cold.wall_us, (long long)cold.cpu_us);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_wide(void)
{
    int failures = 0;
    TEST_CASE("check seam: wider selection still executes") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter wide;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_quorum(&f, &key));
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 2));
        ASSERT(seam_run(&in, dir, binary, 2, f.rx, &f.domain, &policy, &wide));
        ASSERT(wide.out.ok);
        ASSERT_EQ(wide.out.test_children, 1u);
        ASSERT_EQ(wide.out.reused, 0u);
        ASSERT_EQ(wide.out.ran, 2u);
        printf("check_seam case=wide children=%u reused=%u ok=%d\n",
               wide.out.test_children, wide.out.reused, wide.out.ok ? 1 : 0);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_domain(void)
{
    int failures = 0;
    TEST_CASE("check seam: same-domain signer does not skip") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        uint8_t verifiers[1][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter run;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        memcpy(verifiers[0], f.pub[PTF_AUTHOR], 32);
        policy.verifiers = (const uint8_t (*)[32])verifiers;
        policy.verifier_count = 1;
        policy.quorum = 1;
        ASSERT(seam_pass_sync(&f, PTF_AUTHOR, &key, ptf_pass()));
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, f.rx, &f.domain, &policy, &run));
        ASSERT(run.out.ok);
        ASSERT_EQ(run.out.test_children, 1u);
        ASSERT_EQ(run.out.reused, 0u);
        printf("check_seam case=domain children=%u reused=%u ok=%d\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_conflict(void)
{
    int failures = 0;
    TEST_CASE("check seam: observation conflict blocks") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter run;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_pass_sync(&f, PTF_A, &key, ptf_pass()));
        ASSERT(seam_pass_sync(&f, PTF_B, &key, ptf_pass()));
        ASSERT(seam_pass_sync(&f, PTF_C, &key, ptf_fail()));
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, f.rx, &f.domain, &policy, &run));
        ASSERT(!run.out.ok);
        ASSERT_EQ(run.out.test_children, 0u);
        ASSERT_EQ(run.out.reused, 0u);
        ASSERT(!run.out.log_present);
        ASSERT(strstr(run.out.why, VCS_PROOF_OBSERVATION_CONFLICT) != NULL);
        printf("check_seam case=conflict children=%u reused=%u ok=%d why=%s\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0,
               run.out.why);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_changed(void)
{
    int failures = 0;
    TEST_CASE("check seam: changed closure executes") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter run;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_quorum(&f, &key));
        raw[0][31] ^= 0x01;
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, f.rx, &f.domain, &policy, &run));
        ASSERT(run.out.ok);
        ASSERT_EQ(run.out.test_children, 1u);
        ASSERT_EQ(run.out.reused, 0u);
        printf("check_seam case=changed children=%u reused=%u ok=%d\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_incomplete(void)
{
    int failures = 0;
    TEST_CASE("check seam: incomplete closure executes") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter run;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_quorum(&f, &key));
        in.source_cas = NULL;
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, f.rx, &f.domain, &policy, &run));
        ASSERT(run.out.ok);
        ASSERT_EQ(run.out.test_children, 1u);
        ASSERT_EQ(run.out.reused, 0u);
        printf("check_seam case=incomplete children=%u reused=%u ok=%d\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_reused_basis(void)
{
    int failures = 0;
    TEST_CASE("check seam: REUSED-basis tickets do not skip") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        uint8_t root[32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct ptf_spec reused;
        struct seam_meter run;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(ptf_emit(&f, PTF_A, &key, ptf_pass(), NULL, root));
        reused = ptf_pass();
        reused.basis = VCS_PROOF_BASIS_REUSED;
        reused.basis_ref = root;
        ASSERT(seam_pass_sync(&f, PTF_A, &key, reused));
        ASSERT(seam_pass_sync(&f, PTF_B, &key, reused));
        ASSERT(seam_pass_sync(&f, PTF_C, &key, reused));
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, f.rx, &f.domain, &policy, &run));
        ASSERT(run.out.ok);
        ASSERT_EQ(run.out.test_children, 1u);
        ASSERT_EQ(run.out.reused, 0u);
        printf("check_seam case=reused_basis children=%u reused=%u ok=%d\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_stale(void)
{
    int failures = 0;
    TEST_CASE("check seam: stale observations do not skip") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter run;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_quorum(&f, &key));
        policy.now_unix = 1790000000ull + 100000ull;
        policy.max_age_seconds = 10;
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, f.rx, &f.domain, &policy, &run));
        ASSERT(run.out.ok);
        ASSERT_EQ(run.out.test_children, 1u);
        ASSERT_EQ(run.out.reused, 0u);
        printf("check_seam case=stale children=%u reused=%u ok=%d\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0);
        ptf_free(&f);
    } TEST_END
    return failures;
}

static int seam_case_revoked(void)
{
    int failures = 0;
    TEST_CASE("check seam: revoked verifiers do not skip") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        uint8_t revoked[2][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter run;
        char dir[SEAM_PATH], binary[SEAM_PATH];
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_quorum(&f, &key));
        memcpy(revoked[0], f.pub[PTF_A], 32);
        memcpy(revoked[1], f.pub[PTF_B], 32);
        policy.revoked = (const uint8_t (*)[32])revoked;
        policy.revoked_count = 2;
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, f.rx, &f.domain, &policy, &run));
        ASSERT(run.out.ok);
        ASSERT_EQ(run.out.test_children, 1u);
        ASSERT_EQ(run.out.reused, 0u);
        printf("check_seam case=revoked children=%u reused=%u ok=%d\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0);
        ptf_free(&f);
    } TEST_END
    return failures;
}

/* One issuer signs the derived closure and one earlier ticket. Compaction
 * drops the earlier covered ticket, so a rebuilt receiver isolates that
 * issuer. The closure key then has no eligible quorum. */
#define SEAM_STORE_QUOTA (UINT64_C(64) * 1024u * 1024u)

static bool seam_store_put(struct vcs_package_store *store,
                           const uint8_t *wire, size_t len)
{
    uint8_t root[32];
    return vcs_proof_ticket_store_put(store, wire, len, root);
}

static bool seam_emit_pair(struct ptf *f,
                           const struct vcs_component_proof_key_v1 *closure,
                           uint8_t cover[VCS_PROOF_TICKET_WIRE_BYTES],
                           uint8_t pass[VCS_PROOF_TICKET_WIRE_BYTES],
                           uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES])
{
    struct vcs_component_proof_key_v1 other = *closure;
    ptf_root(VCS_CPK_UNIT_ID, "proof-check-cover",
             other.roots[VCS_CPK_UNIT_ID]);
    return ptf_emit(f, PTF_A, &other, ptf_pass(), cover, NULL) &&
           ptf_emit(f, PTF_A, closure, ptf_pass(), pass, NULL) &&
           vcs_proof_issuer_log_checkpoint(f->logs[PTF_A], 90, cp);
}

/* Staging is one tenth of the tightened quota. The three history blobs
 * alone make that tenth smaller than one ticket, and the eviction write
 * is then refused. This ballast keeps the rare pool large enough. */
static bool seam_store_ballast(struct vcs_package_store *store)
{
    uint8_t blob[8000];
    memset(blob, 0x5a, sizeof(blob));
    return seam_store_put(store, blob, sizeof(blob));
}

static bool seam_store_wires(const char *dir, const uint8_t *cover,
                             const uint8_t *pass, const uint8_t *cp)
{
    struct vcs_package_store *store = vcs_package_store_open(dir,
                                                             SEAM_STORE_QUOTA);
    bool ok = store &&
              seam_store_put(store, cover, VCS_PROOF_TICKET_WIRE_BYTES) &&
              seam_store_put(store, pass, VCS_PROOF_TICKET_WIRE_BYTES) &&
              seam_store_put(store, cp, VCS_PROOF_CHECKPOINT_WIRE_BYTES) &&
              seam_store_ballast(store);
    if (store) vcs_package_store_close(store);
    return ok;
}

/* `victim` is marked rare under a quota that fits the pins and one more
 * write of the same size, so that write evicts exactly the covered ticket. */
static bool seam_compact_cover(const char *dir, const uint8_t *victim,
                               size_t len)
{
    struct vcs_package_store *store = vcs_package_store_open(dir,
                                                             SEAM_STORE_QUOTA);
    uint64_t rare, pins, tight;
    uint8_t root[32];
    uint8_t junk[VCS_PROOF_TICKET_WIRE_BYTES + 1u];
    size_t got = 0;
    bool ok;
    if (!store) return false;
    rare = vcs_package_store_pool_usage(store, VCS_PACKAGE_STORE_POOL_RARE);
    pins = vcs_package_store_pool_usage(store, VCS_PACKAGE_STORE_POOL_PINS);
    vcs_package_store_close(store);
    tight = (rare / 3u) * 10u + 10u;
    if (tight < pins * 5u + 10u) tight = pins * 5u + 10u;
    store = vcs_package_store_open(dir, tight);
    ok = store && len <= VCS_PROOF_TICKET_WIRE_BYTES &&
         vcs_blob_root(victim, len, root) &&
         vcs_package_store_set_class(store, root, VCS_PACKAGE_STORE_CLASS_RARE,
                                     1000u) == VCS_PACKAGE_STORE_OK;
    if (ok) {
        memset(junk, 0x41, len);
        ok = seam_store_put(store, junk, len) &&
             vcs_blob_get_from(store, root, junk, sizeof(junk), &got) ==
                 VCS_BLOB_ERR_ABSENT;
    }
    if (store) vcs_package_store_close(store);
    return ok;
}

static struct vcs_proof_receiver *seam_rebuild(
    const char *dir, const struct vcs_proof_reuse_policy *policy)
{
    struct vcs_package_store *store = vcs_package_store_open(dir,
                                                             SEAM_STORE_QUOTA);
    struct vcs_proof_receiver *rx = store ? vcs_proof_receiver_new() : NULL;
    size_t tickets = 0, cps = 0, skipped = 0;
    uint64_t generation = 0;
    bool ok = rx && vcs_proof_receiver_rebuild_with_policy(
                        rx, store, policy, NULL, 0, 64u, &tickets, &cps,
                        &skipped, &generation);
    if (store) vcs_package_store_close(store);
    if (!ok) {
        vcs_proof_receiver_free(rx);
        return NULL;
    }
    return rx;
}

/* Same admission inputs the CHECK dimension passes: known scope, the
 * derived key, and this rebuilt receiver. */
static bool seam_history_reason(const struct vcs_proof_receiver *rx,
                                const struct vcs_component_proof_key_v1 *key,
                                const struct vcs_proof_candidate_domain *domain,
                                const struct vcs_proof_reuse_policy *policy,
                                const char **why)
{
    struct vcs_proof_admission_context ctx = {
        .receiver = rx, .domain = domain, .policy = policy,
    };
    struct vcs_proof_change change = {0};
    struct vcs_proof_obligation obligation = {0};
    struct vcs_proof_admission_result result;
    struct vcs_proof_admission_report report;
    change.component_id = "proof-check-group";
    change.scope_known = true;
    memcpy(change.contract_root_before,
           key->roots[VCS_CPK_INTEGRATION_EDGES], 32);
    memcpy(change.contract_root_after,
           key->roots[VCS_CPK_INTEGRATION_EDGES], 32);
    obligation.name = "proof-check-group";
    obligation.component_id = "proof-check-group";
    obligation.action_class = VCS_PROOF_ACTION_CHECK;
    obligation.preimage = key;
    obligation.in_reach = true;
    if (!vcs_proof_admission_run(&ctx, &change, &obligation, 1, &result,
                                 &report))
        return false;
    *why = result.reason;
    return result.status == VCS_PROOF_ADMIT_FRESH &&
           result.decision.outcome == VCS_PROOF_REUSE_MISS;
}

static int seam_case_history(void)
{
    int failures = 0;
    TEST_CASE("check seam: missing issuer history launches") {
        struct ptf f;
        uint8_t raw[SEAM_RAW][32];
        struct zcl_dev_proof_check_inputs in;
        struct vcs_component_proof_key_v1 key;
        struct vcs_proof_reuse_policy policy;
        struct seam_meter run;
        uint8_t cover[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t pass[VCS_PROOF_TICKET_WIRE_BYTES];
        uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
        char store_dir[SEAM_PATH], dir[SEAM_PATH], binary[SEAM_PATH];
        const char *why = NULL;
        struct vcs_proof_receiver *rx;
        ASSERT(ptf_init(&f));
        seam_fill(raw, &in);
        ASSERT(seam_align(&f, &in, &key, &policy));
        ASSERT(seam_emit_pair(&f, &key, cover, pass, cp));
        ASSERT(test_mkdtemp(store_dir, sizeof(store_dir),
                            "z23-check-seam-store") != NULL);
        ASSERT(seam_store_wires(store_dir, cover, pass, cp));
        ASSERT(seam_compact_cover(store_dir, cover,
                                  VCS_PROOF_TICKET_WIRE_BYTES));
        rx = seam_rebuild(store_dir, &policy);
        ASSERT(rx != NULL);
        ASSERT(vcs_proof_receiver_issuer_history_incomplete(rx, f.pub[PTF_A]));
        ASSERT(seam_history_reason(rx, &key, &f.domain, &policy, &why));
        ASSERT(why && strcmp(why, VCS_PROOF_REUSE_WHY_HISTORY_INCOMPLETE) == 0);
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, rx, &f.domain, &policy, &run));
        ASSERT(run.out.ok);
        ASSERT_EQ(run.out.test_children, 1u);
        ASSERT_EQ(run.out.reused, 0u);
        ASSERT(run.out.log_present);
        printf("check_seam case=history children=%u reused=%u ok=%d why=%s\n",
               run.out.test_children, run.out.reused, run.out.ok ? 1 : 0, why);
        vcs_proof_receiver_free(rx);
        test_rm_rf(store_dir);
        ptf_free(&f);
    } TEST_END
    return failures;
}

/* The loader token the worker records. A successful load is still not
 * a test-verdict signer, so the token is verifier_unqualified rather
 * than an adopted key. */
static bool seam_trust_token(char *token, size_t cap)
{
    struct zcl_verify_attest_box_key box;
    struct zcl_verify_attest_trust_root root;
    const char *why = NULL;
    const char *got;
    int n;
    zcl_verify_receiver_box_key(&box);
    if (!zcl_verify_attest_trust_root_load(NULL, &box, &root, &why))
        got = why && why[0] ? why : ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY;
    else
        got = "verifier_unqualified";
    n = snprintf(token, cap, "%s", got);
    return n > 0 && (size_t)n < cap;
}

/* A private state root so derivation does not depend on this box
 * already having a proof signer. The previous XDG value is restored
 * by seam_signer_end, including when it was unset. */
static bool seam_signer_begin(char *dir, size_t dir_cap, char *old,
                              size_t old_cap, uint8_t pub[32])
{
    const char *prev = getenv("XDG_STATE_HOME");
    const char *why = NULL;
    uint8_t sig[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES];
    static const uint8_t zero[32];
    char *made;
    size_t n;
    dir[0] = 0;
    old[0] = 0;
    if (prev) {
        n = strlen(prev);
        if (n + 1 > old_cap) return false;
        memcpy(old, prev, n + 1);
    }
    made = test_mkdtemp(dir, dir_cap, "z23-check-seam-signer");
    if (!made) return false;
    if (setenv("XDG_STATE_HOME", dir, 1) != 0) return false;
    if (!zcl_dev_proof_signer_sign((const uint8_t *)"check-seam", 10, pub,
                                   sig, &why))
        return false;
    return memcmp(pub, zero, 32) != 0;
}

static void seam_signer_end(const char *dir, const char *old)
{
    if (old && old[0]) {
        if (setenv("XDG_STATE_HOME", old, 1) != 0)
            (void)unsetenv("XDG_STATE_HOME");
    } else {
        (void)unsetenv("XDG_STATE_HOME");
    }
    if (dir && dir[0]) test_rm_rf(dir);
}

/* Null authority is derived inside the dimension. The signer lives
 * under the private state root from seam_signer_begin. The trust
 * token is the loader's own result, and a loaded compile key still
 * does not skip the test child. */
static int seam_case_derived(void)
{
    int failures = 0;
    char state[SEAM_PATH], old[SEAM_PATH], trust[64];
    char dir[SEAM_PATH], binary[SEAM_PATH];
    uint8_t raw[SEAM_RAW][32];
    uint8_t pub[32];
    struct zcl_dev_proof_check_inputs in;
    struct vcs_component_proof_key_v1 key;
    struct seam_meter derived;
    int policy_matches;
    int author_matches;
    state[0] = 0;
    if (!seam_signer_begin(state, sizeof(state), old, sizeof(old), pub)) {
        printf("FAIL check seam signer isolate\n");
        failures++;
        seam_signer_end(state, old);
        return failures;
    }
    TEST_CASE("check seam: unset authority is derived from the closure") {
        seam_fill(raw, &in);
        ASSERT(zcl_dev_proof_check_closure_derive(&in, &key));
        ASSERT(seam_trust_token(trust, sizeof(trust)));
        ASSERT(seam_dir(dir, sizeof(dir), binary, sizeof(binary), 1));
        ASSERT(seam_run(&in, dir, binary, 1, NULL, NULL, NULL, &derived));
        ASSERT(derived.out.ok);
        ASSERT_EQ(derived.out.test_children, 1u);
        ASSERT_EQ(derived.out.reused, 0u);
        ASSERT(derived.out.authority_derived);
        ASSERT(derived.out.authority_local_signer);
        policy_matches = memcmp(derived.out.derived_policy_root,
                                key.roots[VCS_CPK_POLICY], 32) == 0;
        author_matches = memcmp(derived.out.derived_author, pub, 32) == 0;
        ASSERT(policy_matches);
        ASSERT(author_matches);
        ASSERT(strcmp(derived.out.authority_trust, trust) == 0);
        ASSERT(strstr(derived.out.why,
                      "unqualified(no_verifier_account)") != NULL);
        printf("check_seam case=derived children=%u reused=%u derived=1 "
               "local_signer=1 policy_matches=%d author_matches=%d "
               "trust=%s why=%s\n",
               derived.out.test_children, derived.out.reused, policy_matches,
               author_matches, derived.out.authority_trust, derived.out.why);
        test_rm_rf(dir);
    } TEST_END
    seam_signer_end(state, old);
    return failures;
}

/* A directory this process owns is the same trust domain the proof
 * refuses. /usr is root-owned on this host, so the uid compare is the
 * branch that runs, and no verifier is qualified for it. */
static int seam_case_same_uid(void)
{
    int failures = 0;
    TEST_CASE("check seam: same-uid donor stays refused") {
        char dir[SEAM_PATH];
        char *made = test_mkdtemp(dir, sizeof(dir), "z23-check-seam-uid");
        struct stat st;
        const char *own;
        const char *other;
        ASSERT(made != NULL);
        ASSERT(lstat("/usr", &st) == 0);
        ASSERT(st.st_uid != geteuid());
        own = zcl_dev_proof_test_donor_trust_name(dir);
        other = zcl_dev_proof_test_donor_trust_name("/usr");
        ASSERT(own != NULL);
        ASSERT(strcmp(own, "donor_untrusted_same_uid") == 0);
        ASSERT(other != NULL);
        ASSERT(strcmp(other, "donor_verifier_unqualified") == 0);
        printf("check_seam case=same_uid own=%s other=%s\n", own, other);
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

static int seam_case_cached(void)
{
    int failures = 0;
    TEST_CASE("check seam: groups_cached without a vouch is not reuse") {
        char dir[SEAM_PATH];
        char *made = test_mkdtemp(dir, sizeof(dir), "z23-check-seam-log");
        char path[SEAM_PATH];
        struct zcl_dev_proof_dimension dim = {.selected = 1};
        FILE *f;
        ASSERT(made != NULL);
        ASSERT(snprintf(path, sizeof(path), "%s/verdict.log", dir) <
               (int)sizeof(path));
        f = fopen(path, "w");
        ASSERT(f != NULL);
        ASSERT(fprintf(f,
                       "SUITE VERDICT mode=cold groups_total=1 groups_ran=0 "
                       "groups_cached=1 groups_gated=0 groups_failed=0 "
                       "self_skips=0 env_unobserved=0\n") > 0);
        ASSERT(fclose(f) == 0);
        ASSERT(!zcl_dev_proof_test_log_account(path, &dim, NULL, 0));
        printf("check_seam case=groups_cached accounted=0\n");
    } TEST_END
    return failures;
}

/* The land outcome is this string. A bare test_accounting_incomplete is a
 * miss: the author already paid for the whole proof. */
static int seam_account_is(const char *dir, const char *body,
                           uint32_t selected, const char *want)
{
    char path[SEAM_PATH];
    char why[160];
    struct zcl_dev_proof_dimension dim = {.selected = selected};
    FILE *f;
    if (snprintf(path, sizeof path, "%s/verdict.log", dir) >= (int)sizeof path)
        return 1;
    f = fopen(path, "w");
    if (!f)
        return 1;
    if (body && fprintf(f, "%s", body) < 0) {
        fclose(f);
        return 1;
    }
    if (fclose(f) != 0)
        return 1;
    why[0] = 'x';
    if (want) {
        if (zcl_dev_proof_test_log_account(path, &dim, why, sizeof why) ||
            strcmp(why, want) != 0) {
            printf("account why got=\"%s\" want=\"%s\"\n", why, want);
            return 1;
        }
        return 0;
    }
    return zcl_dev_proof_test_log_account(path, &dim, why, sizeof why) &&
                   why[0] == '\0'
               ? 0
               : 1;
}

static int seam_case_account_why(void)
{
    int failures = 0;
    TEST_CASE("check seam: accounting refusal names the mismatched count") {
        char dir[SEAM_PATH];
        char *made = test_mkdtemp(dir, sizeof(dir), "z23-check-seam-why");
        const char *cold =
            "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
            "groups_cached=0 groups_gated=0 groups_failed=0 self_skips=0 "
            "env_unobserved=0\n";
        ASSERT(made != NULL);
        ASSERT(seam_account_is(dir, NULL, 1,
                               "test_accounting_incomplete:no_suite_verdict") ==
               0);
        ASSERT(seam_account_is(dir, "SUITE VERDICT mode=cold groups_total=1\n",
                               1, "test_accounting_incomplete:verdict_fields") ==
               0);
        ASSERT(seam_account_is(
                   dir,
                   "SUITE VERDICT mode=cold groups_total=2 groups_ran=1 "
                   "groups_cached=0 groups_gated=0 groups_failed=0 "
                   "self_skips=0 env_unobserved=0\n",
                   1,
                   "test_accounting_incomplete:groups_total=2 ran=1 cached=0 "
                   "gated=0") == 0);
        ASSERT(seam_account_is(
                   dir,
                   "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
                   "groups_cached=0 groups_gated=0 groups_failed=0 "
                   "self_skips=0 env_unobserved=0\n",
                   2, "test_accounting_incomplete:groups_ran=1 selected=2") ==
               0);
        ASSERT(seam_account_is(
                   dir,
                   "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
                   "groups_cached=0 groups_gated=0 groups_failed=1 "
                   "self_skips=0 env_unobserved=0\n",
                   1, "test_accounting_incomplete:groups_failed=1") == 0);
        ASSERT(seam_account_is(
                   dir,
                   "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
                   "groups_cached=0 groups_gated=0 groups_failed=0 "
                   "self_skips=1 env_unobserved=0\n",
                   1, "test_accounting_incomplete:self_skips=1") == 0);
        ASSERT(seam_account_is(
                   dir,
                   "SUITE VERDICT mode=cold groups_total=1 groups_ran=1 "
                   "groups_cached=0 groups_gated=0 groups_failed=0 "
                   "self_skips=0 env_unobserved=3\n",
                   1, "test_accounting_incomplete:env_unobserved=3") == 0);
        ASSERT(seam_account_is(
                   dir,
                   "SUITE VERDICT mode=cold groups_total=1 groups_ran=0 "
                   "groups_cached=1 groups_gated=0 groups_failed=0 "
                   "self_skips=0 env_unobserved=0\n",
                   1, "test_reuse_unqualified_no_verifier_account") == 0);
        ASSERT(seam_account_is(dir, cold, 1, NULL) == 0);
        printf("check_seam case=account_why\n");
        test_rm_rf(dir);
    } TEST_END
    return failures;
}

int test_proof_ticket_check_seam(void)
{
    int failures = 0;
    failures += seam_case_hit_cold();
    failures += seam_case_wide();
    failures += seam_case_domain();
    failures += seam_case_conflict();
    failures += seam_case_changed();
    failures += seam_case_incomplete();
    failures += seam_case_reused_basis();
    failures += seam_case_stale();
    failures += seam_case_revoked();
    failures += seam_case_history();
    failures += seam_case_derived();
    failures += seam_case_same_uid();
    failures += seam_case_cached();
    failures += seam_case_account_why();
    return failures;
}
