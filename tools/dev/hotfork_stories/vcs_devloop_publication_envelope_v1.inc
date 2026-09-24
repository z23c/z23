/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter vcs-devloop-publication-envelope.v1
 * for contexts/commons/modules/vcs/src/vcs_devloop.c.
 * Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#include "hotswap/hotfork_capsule.h"
#elif ZCL_HOTFORK_STORY_PHASE == 2
__attribute__((visibility("hidden"))) bool
zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out)
{
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
#define HF_CHECK(x) \
    do { \
        out->checks_run++; \
        if (x) \
            out->checks_passed++; \
    } while (0)
    uint8_t zero[32] = {0}, one[32] = {1};
    HF_CHECK(!zcl_bytes_any_set(zero, 32));
    HF_CHECK(zcl_bytes_any_set(one, 32));
    struct vcs_devloop_publication_job job = {
        .version = VCS_DEVLOOP_PUBLICATION_JOB_VERSION};
    memset(job.vcs_commit_root, 1, 32);
    memset(job.source_tree_root, 2, 32);
    memset(job.proof_receipt_root, 3, 32);
    memset(job.source_identity_sha256, 4, 32);
    memset(job.source_cas_sha3, 5, 32);
    job.generation_sha256[0] = 6;
    job.parent_workspace_root[0] = 7;
    uint8_t job_wire[VCS_DEV_PUBLICATION_JOB_WIRE_BYTES];
    HF_CHECK(publication_job_serialize(&job, job_wire));
    struct vcs_devloop_publication_job parsed_job = {0};
    HF_CHECK(publication_job_parse(job_wire, sizeof(job_wire), &parsed_job));
    HF_CHECK(memcmp(&job, &parsed_job, sizeof(job)) == 0);
    uint8_t saved = job_wire[0];
    job_wire[0] ^= 1;
    HF_CHECK(!publication_job_parse(job_wire, sizeof(job_wire), &parsed_job));
    job_wire[0] = saved;
    memset(job.source_tree_root, 0, 32);
    HF_CHECK(!publication_job_serialize(&job, job_wire));
    memset(job.source_tree_root, 2, 32);
    job.version = 2;
    HF_CHECK(!publication_job_serialize(&job, job_wire));
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE,
        .bytes_scanned = 123,
        .new_chunks = 4,
        .reused_chunks = 5,
        .providers = 6,
        .storage_acks = 7};
    memset(receipt.job_root, 8, 32);
    uint8_t receipt_wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    HF_CHECK(publication_receipt_serialize(&receipt, receipt_wire));
    struct vcs_devloop_publication_receipt parsed_receipt = {0};
    HF_CHECK(publication_receipt_parse(receipt_wire, sizeof(receipt_wire),
                                       &parsed_receipt));
    HF_CHECK(memcmp(&receipt, &parsed_receipt, sizeof(receipt)) == 0);
    receipt.phase = VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND;
    HF_CHECK(!publication_receipt_serialize(&receipt, receipt_wire));
    memset(receipt.artifact_root, 9, 32);
    HF_CHECK(publication_receipt_serialize(&receipt, receipt_wire)
             && publication_receipt_parse(receipt_wire, sizeof(receipt_wire),
                                          &parsed_receipt)
             && memcmp(&receipt, &parsed_receipt, sizeof(receipt)) == 0);
    HF_CHECK(!publication_receipt_parse(receipt_wire, sizeof(receipt_wire) - 1,
                                        &parsed_receipt));
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 14 && out->checks_passed == 14;
}
#else
#error "unknown HOT_FORK story phase"
#endif
