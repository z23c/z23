/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter package-policy-boundary-calculation.v1
 * for contexts/commons/modules/vcs/src/package_policy.c.
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
#include <stdio.h>
#include <string.h>
#elif ZCL_HOTFORK_STORY_PHASE == 2
static bool hf_dec(bool allow, const char *rule, struct vcs_policy_decision d)
{
    return d.allow == allow
           && (allow ? d.rule == NULL : d.rule && strcmp(d.rule, rule) == 0);
}
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
    const struct vcs_policy_limits *n =
        vcs_policy_limits_for(VCS_POLICY_TIER_NEW_USER);
    const struct vcs_policy_limits *c =
        vcs_policy_limits_for(VCS_POLICY_TIER_EARNED_CONTRIBUTOR);
    const struct vcs_policy_limits *s =
        vcs_policy_limits_for(VCS_POLICY_TIER_VERIFIED_SEEDER);
    HF_CHECK(
        strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_NEW_USER), "new-user")
            == 0
        && strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_EARNED_CONTRIBUTOR),
                  "earned-contributor")
               == 0
        && strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_VERIFIED_SEEDER),
                  "verified-seeder")
               == 0
        && strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_COUNT), "unknown")
               == 0);
    HF_CHECK(n->publish_per_week == 1 && n->request_burst_per_window == 512
             && c->request_burst_per_window == 1024
             && s->request_burst_per_window == 2048
             && vcs_policy_limits_for(VCS_POLICY_TIER_COUNT) == n);
    HF_CHECK(vcs_policy_ratio_milli(7, 0) == 7000
             && vcs_policy_ratio_milli(5, 2) == 2500
             && vcs_policy_ratio_milli(UINT64_MAX, 1) == UINT64_MAX);
    HF_CHECK(vcs_policy_tier_for(0, UINT64_MAX, 1) == VCS_POLICY_TIER_NEW_USER
             && vcs_policy_tier_for(100, 0, 0)
                    == VCS_POLICY_TIER_EARNED_CONTRIBUTOR
             && vcs_policy_tier_for(500, UINT64_C(256) * 1024 * 1024,
                                    UINT64_C(256) * 1024 * 1024)
                    == VCS_POLICY_TIER_VERIFIED_SEEDER);
    HF_CHECK(vcs_policy_week_start(-1) == -3 && vcs_policy_week_start(0) == -3
             && vcs_policy_week_start(4) == 4);
    HF_CHECK(hf_dec(true, NULL,
                    vcs_policy_check_publish(VCS_POLICY_TIER_NEW_USER, 0))
             && hf_dec(false, VCS_POLICY_RULE_PUBLISH_FREQUENCY,
                       vcs_policy_check_publish(VCS_POLICY_TIER_NEW_USER, 1)));
    HF_CHECK(hf_dec(true, NULL,
                    vcs_policy_check_download(
                        VCS_POLICY_TIER_NEW_USER,
                        VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES - 1, 1))
             && hf_dec(false, VCS_POLICY_RULE_DOWNLOAD_ALLOWANCE,
                       vcs_policy_check_download(
                           VCS_POLICY_TIER_NEW_USER,
                           VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES - 1, 2)));
    HF_CHECK(hf_dec(true, NULL,
                    vcs_policy_check_concurrent_downloads(
                        VCS_POLICY_TIER_NEW_USER, 0))
             && hf_dec(false, VCS_POLICY_RULE_CONCURRENT_DOWNLOADS,
                       vcs_policy_check_concurrent_downloads(
                           VCS_POLICY_TIER_NEW_USER, 1)));
    HF_CHECK(hf_dec(false, VCS_POLICY_RULE_PIN_ALLOWANCE,
                    vcs_policy_check_pin(VCS_POLICY_TIER_NEW_USER, 0, 0))
             && hf_dec(true, NULL,
                       vcs_policy_check_pin(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                                            0, 1)));
    HF_CHECK(hf_dec(true, NULL,
                    vcs_policy_check_announce(VCS_POLICY_TIER_NEW_USER, 63))
             && hf_dec(false, VCS_POLICY_RULE_ANNOUNCE_RATE,
                       vcs_policy_check_announce(VCS_POLICY_TIER_NEW_USER, 64)));
    HF_CHECK(
        hf_dec(true, NULL,
               vcs_policy_check_request_burst(VCS_POLICY_TIER_NEW_USER, 511))
        && hf_dec(false, VCS_POLICY_RULE_REQUEST_BURST,
                  vcs_policy_check_request_burst(VCS_POLICY_TIER_NEW_USER, 512))
        && hf_dec(true, NULL,
                  vcs_policy_check_request_burst(
                      VCS_POLICY_TIER_EARNED_CONTRIBUTOR, 1023))
        && hf_dec(false, VCS_POLICY_RULE_REQUEST_BURST,
                  vcs_policy_check_request_burst(
                      VCS_POLICY_TIER_VERIFIED_SEEDER, 2048)));
    HF_CHECK(
        vcs_policy_queue_priority(VCS_POLICY_TIER_NEW_USER) == 0
        && vcs_policy_queue_priority(VCS_POLICY_TIER_EARNED_CONTRIBUTOR) == 1
        && vcs_policy_queue_priority(VCS_POLICY_TIER_VERIFIED_SEEDER) == 2);
    HF_CHECK(
        hf_dec(false, VCS_POLICY_RULE_SELF_VERIFICATION,
               vcs_policy_check_verifier(2000, true, true))
        && hf_dec(false, VCS_POLICY_RULE_VERIFIER_SCORE,
                  vcs_policy_check_verifier(999, true, false))
        && hf_dec(false, VCS_POLICY_RULE_VERIFIER_APPROVED,
                  vcs_policy_check_verifier(1000, false, false))
        && hf_dec(true, NULL, vcs_policy_check_verifier(1000, true, false)));
    static const char *const nc[] = {
        "announcement-bytes", "unverified-bytes", "duplicate-request-replay",
        "unrequested-bytes",  "invalid-chunk",    "incomplete-staging"};
    bool names = true;
    for (int i = 0; i < VCS_POLICY_NO_CREDIT_COUNT; i++)
        names =
            names
            && strcmp(vcs_policy_no_credit_string((enum vcs_policy_no_credit)i),
                      nc[i])
                   == 0;
    HF_CHECK(names
             && strcmp(vcs_policy_no_credit_string(VCS_POLICY_NO_CREDIT_COUNT),
                       "unknown")
                    == 0);
    static const char *const off[] = {"duplicate-request", "unrequested-bytes",
                                      "invalid-chunk", "announce-flood",
                                      "request-flood"};
    names = true;
    for (int i = 0; i < VCS_POLICY_OFFENCE_COUNT; i++)
        names = names
                && strcmp(vcs_policy_offence_string((enum vcs_policy_offence)i),
                          off[i])
                       == 0;
    HF_CHECK(names
             && strcmp(vcs_policy_offence_string(VCS_POLICY_OFFENCE_COUNT),
                       "unknown")
                    == 0);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 15 && out->checks_passed == 15;
}
#else
#error "unknown HOT_FORK story phase"
#endif
