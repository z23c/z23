/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Pin that tip_finalize_trusted_anchor_at stays silent for the normal
 * anchor row above an older trusted base, still WARNs (throttled) on a real
 * same-height disagreement, and never changes its return value. */
#ifndef ZCL_TIP_FINALIZE_TRUSTED_ANCHOR_LOG_TEST_H
#define ZCL_TIP_FINALIZE_TRUSTED_ANCHOR_LOG_TEST_H

static int trusted_anchor_log_above_base(struct synth_chain_tf *sc)
{
    int failures = 0;
    for (int h = 4; h <= 5; h++) {
        struct uint256 hash = sc->hashes[h];
        TF_CHECK("trusted_anchor_log: seed anchor row above base",
                 log_insert(progress_store_db(), h, "anchor", true, NULL, 0,
                            0, &hash));
        TF_CHECK("trusted_anchor_log: row above older base is not exact",
                 tip_finalize_trusted_anchor_at(progress_store_db(), h,
                                                &hash) == 0);
    }
    TF_CHECK("trusted_anchor_log: normal raise-only state emits no WARN",
             tip_finalize_trusted_mismatch_warn_count_for_testing() == 0);
    return failures;
}

static int trusted_anchor_log_same_height(struct synth_chain_tf *sc)
{
    int failures = 0;
    TF_CHECK("trusted_anchor_log: corrupt trusted hash at same height",
             progress_meta_set(progress_store_db(),
                               REDUCER_TRUSTED_BASE_HASH_KEY,
                               sc->hashes[2].data,
                               sizeof(sc->hashes[2].data)));
    for (int i = 0; i < 3; i++)
        TF_CHECK("trusted_anchor_log: same-height disagreement refused",
                 tip_finalize_trusted_anchor_at(progress_store_db(), 3,
                                                &sc->hashes[3]) == 0);
    TF_CHECK("trusted_anchor_log: same-height disagreement WARNs once",
             tip_finalize_trusted_mismatch_warn_count_for_testing() == 1);
    return failures;
}

static int trusted_anchor_log_base_above_row(struct synth_chain_tf *sc)
{
    int failures = 0;
    struct uint256 hash = sc->hashes[2];
    tip_finalize_trusted_mismatch_reset_for_testing();
    TF_CHECK("trusted_anchor_log: seed anchor row below base",
             log_insert(progress_store_db(), 2, "anchor", true, NULL, 0,
                        0, &hash));
    TF_CHECK("trusted_anchor_log: base above row is refused",
             tip_finalize_trusted_anchor_at(progress_store_db(), 2,
                                            &hash) == 0);
    TF_CHECK("trusted_anchor_log: base above row WARNs once",
             tip_finalize_trusted_mismatch_warn_count_for_testing() == 1);
    return failures;
}

static int trusted_anchor_log_no_base(struct synth_chain_tf *sc)
{
    int failures = 0;
    tip_finalize_trusted_mismatch_reset_for_testing();
    TF_CHECK("trusted_anchor_log: drop trusted base height",
             progress_meta_delete(progress_store_db(),
                                  REDUCER_TRUSTED_BASE_HEIGHT_KEY));
    TF_CHECK("trusted_anchor_log: drop trusted base hash",
             progress_meta_delete(progress_store_db(),
                                  REDUCER_TRUSTED_BASE_HASH_KEY));
    TF_CHECK("trusted_anchor_log: missing base is refused",
             tip_finalize_trusted_anchor_at(progress_store_db(), 2,
                                            &sc->hashes[2]) == 0);
    TF_CHECK("trusted_anchor_log: missing base WARNs once",
             tip_finalize_trusted_mismatch_warn_count_for_testing() == 1);
    return failures;
}

static int case_trusted_anchor_log(void)
{
    int failures = 0;
    char dir[256]; struct main_state ms; struct synth_chain_tf sc;
    tip_finalize_trusted_mismatch_reset_for_testing();
    TF_CHECK("trusted_anchor_log: setup",
             tf_setup("trusted_anchor_log", 6, TF_FAIL_NONE, -1,
                      dir, sizeof(dir), &ms, &sc) == 0);
    TF_CHECK("trusted_anchor_log: seed trusted base",
             tip_finalize_stage_seed_anchor(3, sc.hashes[3].data, true));
    failures += trusted_anchor_log_above_base(&sc);
    failures += trusted_anchor_log_same_height(&sc);
    failures += trusted_anchor_log_base_above_row(&sc);
    failures += trusted_anchor_log_no_base(&sc);
    tf_teardown(dir, &ms, &sc);
    return failures;
}

#endif /* ZCL_TIP_FINALIZE_TRUSTED_ANCHOR_LOG_TEST_H */
