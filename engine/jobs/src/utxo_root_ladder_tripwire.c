/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See utxo_root_ladder_tripwire.h for the contract. */

#include "utxo_root_ladder_tripwire.h"

#include "base/text_fit.h"
#include "chain/mmr.h"                        /* MMR_COMMITMENT_INTERVAL */
#include "event/event.h"                       /* EV_UTXO_DRIFT_DETECTED */
#include "models/utxo_root_ladder_verify.h"
#include "storage/progress_store.h"            /* progress_store_db() */
#include "util/blocker.h"
#include "util/log_macros.h"

#include "utxo_apply_log_store.h"              /* utxo_apply_log_insert (H* cap) */

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define UTXO_LADDER_BLOCKER_ID "utxo_ladder_mismatch"

/* Fail-closed cap: write an ok=0 utxo_apply_log verdict at the first divergent
 * boundary. The (untouched) reducer_frontier H* fold treats any ok=0 row in a
 * success-checked log as a contiguity terminator, so H* caps at
 * first_divergent_height-1 and no trusted base can re-anchor above it
 * (utxo_apply_log is in reducer_frontier's trusted_base_fail_disproves_seed
 * set). This is the SAME lever utxo_apply's shielded-anchor reject uses to hold
 * H* (utxo_apply_anchors.c): divergence over frozen history must STOP advance,
 * not just log. NOTE: at the single compiled rung (== the SHA3 checkpoint /
 * finality floor) the fold clamps H* up to the floor, so the cap is a no-op
 * there and the checkpoint-content boot gate is the operative guard; the cap is
 * the general mechanism for any rung ABOVE the floor. */
static void utxo_ladder_cap_hstar(sqlite3 *db, int32_t first_divergent_height)
{
    if (!db || first_divergent_height < 0)
        return;
    (void)utxo_apply_log_ensure_schema(db);
    if (!utxo_apply_log_insert(db, first_divergent_height,
                               "utxo_root_ladder_divergent", /*ok=*/false,
                               0, 0, 0, "utxo-root-ladder-divergent", NULL))
        LOG_WARN("utxo_ladder",
                 "[utxo_ladder] fail-closed H* cap write failed h=%d "
                 "(divergence blocker still set)", first_divergent_height);
}

enum utxo_root_ladder_tripwire_result
utxo_root_ladder_tripwire_report(sqlite3 *db,
                                 const struct utxo_root_ladder_verify_result *results,
                                 size_t n)
{
    /* COVERAGE pair for this call — identical on every entry `results`
     * writes (struct utxo_root_ladder_verify_result's doc comment). This
     * is REPORTING-ONLY telemetry: it is read here to pick a verdict
     * label, never to gate accept/reject, a blocker, or the H* cap —
     * those still key exclusively off `divergent` below, unchanged from
     * before this fix. */
    size_t compared = (results && n > 0) ? results[0].compared : 0;
    size_t total    = (results && n > 0) ? results[0].total    : n;

    if (!results || n == 0) {
        LOG_INFO("utxo_ladder",
                "UNVERIFIED: no ladder rungs examined this call (n=%zu) — "
                "nothing to compare yet; NOT a HEALTHY verdict", n);
        return UTXO_ROOT_LADDER_TRIPWIRE_UNVERIFIED;
    }

    int32_t first_divergent_height = -1;
    size_t divergent = 0;
    for (size_t i = 0; i < n; i++) {
        if (results[i].status == UTXO_ROOT_LADDER_VERIFY_DIVERGENT) {
            if (divergent == 0)
                first_divergent_height = results[i].height;
            divergent++;
        }
    }

    if (divergent == 0) {
        if (compared == 0) {
            /* AGREEMENT (divergent==0) alone is a VACUOUS pass here: every
             * examined rung was NOT_YET_REACHED, so nothing was actually
             * byte-compared this call (COVERAGE == 0). This is exactly the
             * shape that let the shipped ladder (count==1, its one rung
             * absent from this node's own boundary-root store) read as
             * HEALTHY before this fix. Report UNVERIFIED instead — purely
             * a reporting distinction: no blocker, no cap, same (zero)
             * side effects as HEALTHY, E13-neutral. */
            LOG_INFO("utxo_ladder",
                    "UNVERIFIED: compared=0 of total=%zu locked rung(s) — "
                    "no comparison has actually happened on this node yet; "
                    "NOT a HEALTHY verdict", total);
            return UTXO_ROOT_LADDER_TRIPWIRE_UNVERIFIED;
        }
        return UTXO_ROOT_LADDER_TRIPWIRE_HEALTHY;  /* >=1 rung genuinely
            * found + compared (compared > 0) and none of them diverged */
    }

    /* The ladder is an immutable commitment over frozen history, so a divergence
     * here means THIS node's own coins_kv boundary-root store no longer
     * reproduces a value it already locked in — a state-wrong-coin defect, not a
     * transient miss. DEFAULT: fail closed. Escape hatch (owner override) reverts
     * to the historical evidence-only posture. */
    bool observe_only = getenv("ZCL_UTXO_LADDER_OBSERVE_ONLY") != NULL;

    /* The DEFAULT (fail-closed) form previously ran to 324 bytes on its own — a
     * 256-byte local cut it at "...advance holds ", i.e. mid-sentence in the
     * exact clause that tells the operator H* is capped and what lifts the
     * cap; adding the coverage clause below only makes this longer. Build
     * whole into an oversized local, then mark and log the cut via
     * zcl_text_fit() (never silent: it leaves an in-band [cut N/cap] marker
     * and WARN-logs the full untruncated text either way). */
    char full[BLOCKER_REASON_MAX * 2];
    snprintf(full, sizeof(full),
             "utxo root ladder mismatch: %zu of %zu locked rung(s) diverged "
             "(coverage: %zu of %zu compared this call), first at h=%d (this "
             "node's own coins_kv boundary root differs from the locked "
             "golden-height ladder — state-wrong-coin class). %s",
             divergent, n, compared, total, first_divergent_height,
             observe_only
                 ? "OBSERVE-ONLY (ZCL_UTXO_LADDER_OBSERVE_ONLY): H* not capped."
                 : "FAIL-CLOSED: H* capped below the divergent rung; advance "
                   "holds until validated UTXO state is restored (sovereign "
                   "cure, owner-gated).");
    char reason[BLOCKER_REASON_MAX];
    (void)zcl_text_fit(reason, sizeof(reason), full, "utxo_root_ladder_tripwire",
                       "utxo_root_ladder.reason");

    struct blocker_record r;
    if (!blocker_init(&r, UTXO_LADDER_BLOCKER_ID, "utxo_root_ladder_tripwire",
                      observe_only ? BLOCKER_PERMANENT : BLOCKER_DEPENDENCY,
                      reason))
        return UTXO_ROOT_LADDER_TRIPWIRE_MISMATCH;  /* blocker_init logged why */

    if (observe_only) {
        r.escape_deadline_secs = 0;
        r.escape_action[0] = '\0';
    } else {
        /* Enact "stop advance" through the provable-tip fold, then escalate. A
         * non-empty escape_action is REQUIRED for an H*-holding blocker
         * (blocker_stall_meta_detector flags an empty escape as its own defect
         * class). */
        utxo_ladder_cap_hstar(db, first_divergent_height);
        r.escape_deadline_secs = 120;
        snprintf(r.escape_action, sizeof(r.escape_action),
                 "restore validated UTXO state (sovereign cure) + re-verify rung");
    }

    if (blocker_set(&r) == 0)
        event_emitf(EV_UTXO_DRIFT_DETECTED, 0,
                    "verdict=utxo_ladder_mismatch h=%d divergent=%zu of=%zu "
                    "observe_only=%d fail_closed=%d",
                    first_divergent_height, divergent, n,
                    observe_only ? 1 : 0, observe_only ? 0 : 1);

    return UTXO_ROOT_LADDER_TRIPWIRE_MISMATCH;
}

void utxo_root_ladder_tripwire_at_boundary(int height)
{
    /* Operator kill-switch, mirrors ZCL_DISABLE_SHA3_WINDOW_TRIPWIRE.
     * Checked before the (cheap) boundary-cadence gate so it costs nothing
     * either way. */
    if (getenv("ZCL_DISABLE_UTXO_LADDER_TRIPWIRE"))
        return;

    if (height < 0 || (height % MMR_COMMITMENT_INTERVAL) != 0)
        return;   /* only re-check when a fresh boundary root could exist */

    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        return;   /* store not open yet — benign skip */

    struct utxo_root_ladder_verify_result results[256];
    size_t n = 0;
    (void)utxo_root_ladder_verify_against_store(pdb, results,
                                                sizeof(results) / sizeof(results[0]),
                                                &n);
    (void)utxo_root_ladder_tripwire_report(pdb, results, n);
}
