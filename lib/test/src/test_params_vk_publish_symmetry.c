/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The publish/release invariant in lib/sapling/src/params_init.c, pinned for
 * ALL FOUR shielded verifying keys rather than three of them.
 *
 * Four keys arm the four shielded verifiers:
 *
 *   sapling_spend_vk    sapling_check_spend        (sapling.c)
 *   sapling_output_vk   sapling_check_output       (sapling.c)
 *   sprout_vk           sprout_verify_groth16      (sprout.c)
 *   phgr_vk             sprout_verify_phgr13       (bn254.c)
 *
 * Each verifier is fail-closed on a NULL key: "not ready, so reject". That
 * makes the set of published pointers the process's answer to "is shielded
 * validation armed?", and the four must agree on it. They did not. phgr_vk
 * lived in a function-local static inside each of the two load paths, out of
 * reach of the teardown helper, so after sapling_free_params() three verifiers
 * disarmed and sprout_verify_phgr13 was still verifying pre-Sapling JoinSplits
 * (blocks 0-581876) against a key the process had declared released — and each
 * reload dropped the previous ic[] allocation, because ppzksnark_vk_read()
 * memsets its output struct before parsing.
 *
 * What this group pins:
 *
 *   1. Nothing is published before a load runs.
 *   2. A load arms all four together.
 *   3. sapling_free_params() disarms all four together, with no manual
 *      sprout_phgr_set_vk(NULL) to paper over the gap. This is the assertion
 *      that fails against the old code.
 *   4. The PHGR13 key has ONE storage instance: a reload republishes the same
 *      address, which is what makes it reachable from teardown at all.
 *   5. Reload cycles do not accumulate allocations — driven repeatedly so a
 *      dropped ic[] is a finding for any leak-checking run of this group,
 *      and asserted structurally here.
 *   6. The pre-publication release sites cannot disarm a live key set. Every
 *      params_release_groth16_vks() call inside the two loaders sits above
 *      that loader's publish point AND behind the params_loaded early return,
 *      so a load attempted while keys are installed is a no-op that leaves all
 *      four armed. Adding the PHGR13 release to those failure paths would break
 *      exactly this: a node running on the compiled-in keys would lose its
 *      pre-Sapling verifier the first time a directory load failed.
 *
 * Needs no parameter directory and touches no datadir: the compiled-in
 * verifying keys are the whole fixture.
 */

#include "test/test_core.h"

#include "sapling/bls12_381.h"
#include "sapling/bn254.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sapling.h"
#include "sapling/sprout.h"

#include <stdio.h>

#define SYM_CHECK(name, expr) do { \
    printf("params_vk_publish_symmetry: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* How many of the four verifiers are armed right now. The four must never
 * disagree, so the interesting assertions are on 0 and 4 — a 3 is precisely
 * the defect this group exists to catch. */
static int armed_verifier_count(void)
{
    int n = 0;
    if (sapling_test_published_spend_vk() != NULL) n++;
    if (sapling_test_published_output_vk() != NULL) n++;
    if (sprout_test_published_vk() != NULL) n++;
    if (sprout_test_published_phgr_vk() != NULL) n++;
    return n;
}

int test_params_vk_publish_symmetry(void);
int test_params_vk_publish_symmetry(void)
{
    int failures = 0;
    printf("\n=== params VK publish/release symmetry ===\n");

    /* Deterministic baseline. Groups run in their own forked process, but a
     * clean start costs nothing and keeps this readable in isolation. The
     * explicit sprout_phgr_set_vk(NULL) here is baseline setup, NOT a stand-in
     * for the teardown under test — section 3 deliberately does not use it. */
    sapling_free_params();
    sprout_phgr_set_vk(NULL);

    /* ── 1. Nothing published before a load ───────────────────────────── */
    SYM_CHECK("baseline: no verifier is armed", armed_verifier_count() == 0);
    SYM_CHECK("baseline: params report NOT loaded", !sapling_params_loaded());

    /* ── 2. A load arms all four together ─────────────────────────────── */
    SYM_CHECK("installing the compiled-in keys succeeds",
              sapling_install_embedded_vks());
    SYM_CHECK("params report loaded", sapling_params_loaded());
    SYM_CHECK("install arms the spend verifier",
              sapling_test_published_spend_vk() != NULL);
    SYM_CHECK("install arms the output verifier",
              sapling_test_published_output_vk() != NULL);
    SYM_CHECK("install arms the sprout-groth16 verifier",
              sprout_test_published_vk() != NULL);
    SYM_CHECK("install arms the PHGR13 verifier",
              sprout_test_published_phgr_vk() != NULL);
    SYM_CHECK("all four verifiers agree: armed", armed_verifier_count() == 4);

    const struct ppzksnark_vk *phgr_first = sprout_test_published_phgr_vk();
    size_t phgr_ic_len = phgr_first ? phgr_first->ic_len : 0;
    SYM_CHECK("the PHGR13 key carries IC points", phgr_ic_len > 1);

    /* ── 3. Teardown disarms all four together ────────────────────────── */
    /* No sprout_phgr_set_vk(NULL) here. sapling_free_params() must do it, and
     * that is the whole assertion: against the pre-fix code the PHGR13 pointer
     * survived this call and sprout_verify_phgr13 stayed armed while its three
     * siblings had already failed closed. */
    sapling_free_params();
    SYM_CHECK("free_params disarms the spend verifier",
              sapling_test_published_spend_vk() == NULL);
    SYM_CHECK("free_params disarms the output verifier",
              sapling_test_published_output_vk() == NULL);
    SYM_CHECK("free_params disarms the sprout-groth16 verifier",
              sprout_test_published_vk() == NULL);
    SYM_CHECK("free_params disarms the PHGR13 verifier "
              "(no manual sprout_phgr_set_vk(NULL))",
              sprout_test_published_phgr_vk() == NULL);
    SYM_CHECK("all four verifiers agree: disarmed",
              armed_verifier_count() == 0);
    SYM_CHECK("free_params reports params NOT loaded",
              !sapling_params_loaded());

    /* ── 4. One PHGR13 storage instance, reachable from teardown ──────── */
    SYM_CHECK("reinstalling the compiled-in keys succeeds",
              sapling_install_embedded_vks());
    SYM_CHECK("all four verifiers re-arm together",
              armed_verifier_count() == 4);
    SYM_CHECK("the PHGR13 key is ONE file-scope struct, not a per-call static",
              sprout_test_published_phgr_vk() == phgr_first);
    SYM_CHECK("the reloaded PHGR13 key is the same key",
              sprout_test_published_phgr_vk() != NULL &&
              sprout_test_published_phgr_vk()->ic_len == phgr_ic_len);

    /* ── 5. Reload cycles do not accumulate ───────────────────────────── */
    /* ppzksnark_vk_read() memsets before parsing, so a teardown that does not
     * free ic[] drops one allocation per cycle. Drive enough cycles that a
     * leak-checking run of this group reports it, and assert what is
     * observable in-process: the key stays whole and singular. */
    for (int i = 0; i < 8; i++) {
        sapling_free_params();
        if (armed_verifier_count() != 0) {
            printf("params_vk_publish_symmetry: cycle %d left a verifier "
                   "armed after free_params... FAIL\n", i);
            failures++;
            break;
        }
        if (!sapling_install_embedded_vks()) {
            printf("params_vk_publish_symmetry: cycle %d reinstall "
                   "failed... FAIL\n", i);
            failures++;
            break;
        }
    }
    SYM_CHECK("after 8 free/install cycles all four are armed",
              armed_verifier_count() == 4);
    SYM_CHECK("after 8 free/install cycles the PHGR13 storage has not moved",
              sprout_test_published_phgr_vk() == phgr_first);
    SYM_CHECK("after 8 free/install cycles the PHGR13 key is unchanged",
              sprout_test_published_phgr_vk() != NULL &&
              sprout_test_published_phgr_vk()->ic_len == phgr_ic_len);

    /* ── 6. A failed load cannot disarm a live key set ────────────────── */
    /* The keys are installed, so sapling_init_params() returns on its
     * params_loaded early return without opening anything — which is why every
     * params_release_groth16_vks() call inside it is provably pre-publication.
     * The path names a directory that does not exist precisely so that a
     * regression removing that early return would attempt a real load and
     * fail, and the assertions below would then catch the disarm.
     *
     * No datadir is involved: this is a parameter directory, read-only, and it
     * does not exist. */
    SYM_CHECK("a directory load with keys already installed is a no-op",
              sapling_init_params("/nonexistent/params-vk-publish-symmetry"));
    SYM_CHECK("the failed-load path left the spend verifier armed",
              sapling_test_published_spend_vk() != NULL);
    SYM_CHECK("the failed-load path left the output verifier armed",
              sapling_test_published_output_vk() != NULL);
    SYM_CHECK("the failed-load path left the sprout-groth16 verifier armed",
              sprout_test_published_vk() != NULL);
    SYM_CHECK("the failed-load path left the PHGR13 verifier armed "
              "(blocks 0-581876 stay validatable)",
              sprout_test_published_phgr_vk() != NULL);
    SYM_CHECK("all four verifiers still agree: armed",
              armed_verifier_count() == 4);

    /* Leave the process as this group found it. */
    sapling_free_params();
    SYM_CHECK("teardown leaves nothing armed", armed_verifier_count() == 0);

    return failures;
}
