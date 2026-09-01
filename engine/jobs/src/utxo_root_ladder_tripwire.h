/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_root_ladder_tripwire — FAIL-CLOSED production caller for the golden
 * UTXO root ladder verifier (models/utxo_root_ladder_verify.h /
 * chain/utxo_root_ladder.h). Like the SHA3 golden-window tripwire it recomputes
 * nothing new — it compares THIS node's own already-persisted coins_kv
 * boundary-root store (coins_kv_boundary_root_get) against the locked
 * golden-height ladder table. The ladder is an immutable commitment over frozen
 * history, so a byte mismatch means this node's own UTXO state no longer
 * reproduces a value it already locked in: a state-wrong-coin defect, not a
 * transient miss.
 *
 * On divergence it FAILS CLOSED (default): it caps H* below the first divergent
 * rung — by writing an ok=0 utxo_apply_log verdict at that height, the SAME
 * lever utxo_apply's shielded-anchor reject uses (utxo_apply_anchors.c), so the
 * untouched reducer_frontier H* fold terminates its contiguous prefix there and
 * no trusted base can re-anchor above it — and raises an ESCALATING typed
 * blocker (BLOCKER_DEPENDENCY, owner "utxo_root_ladder_tripwire") naming the
 * divergent height. It NEVER touches the chain_linkage_hold accept/reject latch
 * or any consensus validity rule (E13-neutral); "stop advance" is enacted
 * purely through the provable-tip fold, so consensus parity with zclassicd is
 * bit-identical whether or not it fires. The escape hatch env
 * ZCL_UTXO_LADDER_OBSERVE_ONLY reverts to the historical evidence-only posture
 * (a PERMANENT blocker + event, no H* cap); it DEFAULTS to fail-closed.
 *
 * Cadence: only re-checked at MMR_COMMITMENT_INTERVAL (100-block) boundaries
 * — the same cadence tip_finalize_post_step.c persists a fresh boundary root
 * on, so a newly-written root is corroborated at the very next opportunity.
 * The dense mmb_root() layer (utxo_root_ladder_verify_dense_anchor) is
 * DELIBERATELY NOT called from here: it re-folds the ENTIRE leaf-hash
 * pipeline (millions of leaves once past its anchor height) and is only
 * cheap as a rare/opt-in operation — see the ZCL_UTXO_LADDER_HEAVY nightly
 * step (Makefile `simnet-nightly` target) and test_utxo_root_ladder.c's
 * heavy section. The per-rung compare this file drives is O(g_utxo_root_
 * ladder_count) point reads (today count==1), so running it every 100
 * blocks costs nothing measurable on the reducer thread.
 *
 * Internal to engine/jobs/src (not a public jobs/ API) — same convention as
 * tip_finalize_post_step.h. The test group redeclares the entry points it
 * needs directly (see tests/harness/src/test_utxo_root_ladder_tripwire.c). */

#ifndef ZCL_JOBS_UTXO_ROOT_LADDER_TRIPWIRE_H
#define ZCL_JOBS_UTXO_ROOT_LADDER_TRIPWIRE_H

#include <stddef.h>

struct utxo_root_ladder_verify_result;
struct sqlite3;

enum utxo_root_ladder_tripwire_result {
    UTXO_ROOT_LADDER_TRIPWIRE_HEALTHY    = 0,  /* >=1 rung actually FOUND +
                                                * compared this call
                                                * (compared > 0), and none
                                                * of them diverged */
    UTXO_ROOT_LADDER_TRIPWIRE_MISMATCH   = 1,  /* >=1 rung diverged; fail-closed
                                                * (H* capped + blocker + event),
                                                * or observe-only under the hatch */
    UTXO_ROOT_LADDER_TRIPWIRE_UNVERIFIED = 2,  /* NEW: compared == 0 this
                                                * call — NOTHING was actually
                                                * found + byte-compared
                                                * (empty/NULL results, or
                                                * every examined rung was
                                                * NOT_YET_REACHED). This is
                                                * the vacuous-pass shape a
                                                * naive `divergent == 0 =>
                                                * HEALTHY` check cannot tell
                                                * apart from a real pass —
                                                * it is now a DISTINCT value
                                                * so any caller branching on
                                                * `== HEALTHY` cannot mistake
                                                * "nothing verified" for
                                                * "verified and fine". Purely
                                                * a REPORTING distinction:
                                                * no blocker, no H* cap,
                                                * E13-neutral, same as
                                                * HEALTHY's side effects
                                                * (none). Does not replace or
                                                * hide the coverage pair —
                                                * see struct
                                                * utxo_root_ladder_verify_
                                                * result's compared/total,
                                                * which remain the primitive
                                                * a caller should read for
                                                * the raw numbers; this enum
                                                * is only the derived
                                                * scalar. */
};

/* Act on a completed utxo_root_ladder_verify_against_store() call. `results`/`n`
 * are that call's own output array — this reads `results[0].compared` (all
 * entries carry the same coverage pair) when `n > 0`.
 *
 * Verdict precedence (AGREEMENT and COVERAGE compose, they do not collapse
 * into one another):
 *   1. Any rung DIVERGENT (AGREEMENT found a real disagreement, which can
 *      only happen on a compared rung) => MISMATCH, unchanged from before:
 *      registers the `utxo_ladder_mismatch` typed blocker naming the FIRST
 *      divergent rung's height and, by DEFAULT (fail-closed), caps H* below
 *      that height by writing an ok=0 utxo_apply_log verdict there via `db`
 *      (the live progress.kv handle) — so pass the same handle the verify
 *      read from. `db` NULL skips only the cap write (the blocker/event
 *      still fire); the env ZCL_UTXO_LADDER_OBSERVE_ONLY suppresses the cap
 *      and keeps a PERMANENT evidence-only blocker.
 *   2. Else, if COVERAGE is zero (`results` NULL, `n` 0, or every examined
 *      rung is NOT_YET_REACHED so `compared == 0`) => UNVERIFIED. No
 *      blocker, no cap — reporting-only.
 *   3. Else (>=1 rung was actually compared and none diverged) => HEALTHY.
 *      No blocker, no cap. */
enum utxo_root_ladder_tripwire_result
utxo_root_ladder_tripwire_report(struct sqlite3 *db,
                                 const struct utxo_root_ladder_verify_result *results,
                                 size_t n);

/* Run the tripwire iff `height` is an MMR_COMMITMENT_INTERVAL boundary (the
 * cadence a fresh boundary root can appear on) and the operator kill-switch
 * env `ZCL_DISABLE_UTXO_LADDER_TRIPWIRE` is unset. Reads the live
 * progress_store_db() handle; a NULL handle (store not open yet) is a
 * benign skip. Off-boundary heights are a no-op — no db touch, no cost. */
void utxo_root_ladder_tripwire_at_boundary(int height);

#endif /* ZCL_JOBS_UTXO_ROOT_LADDER_TRIPWIRE_H */
