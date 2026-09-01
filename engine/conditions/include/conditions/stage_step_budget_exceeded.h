/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_step_budget_exceeded — OBSERVATIONAL performance-regression naming
 * for the eight reducer stages. See the SYMPTOM/REMEDY/WITNESSED contract
 * below. Never touches a validity predicate and never gates or slows the
 * fold (CLAUDE.md "Consensus parity is inviolable") — it only NAMES a
 * slowdown that would otherwise be silent: stage_step_us_ewma()
 * (platform/modules/util/src/stage.c) is already measured per stage, but nothing
 * consumed it as a budget, so a stage could regress 10x and the cursor
 * would keep moving with no signal. */

#ifndef ZCL_CONDITIONS_STAGE_STEP_BUDGET_EXCEEDED_H
#define ZCL_CONDITIONS_STAGE_STEP_BUDGET_EXCEEDED_H

#include <stdbool.h>
#include <stdint.h>

/* Pipeline order used throughout this condition (index 0..7), matching the
 * fixed reducer stage line in docs/HOW_THE_NODE_WORKS.md and the abbreviated
 * report in engine/composition/src/boot_mint_anchor.c:mint_stage_ewma_collect. */
#define STAGE_BUDGET_NUM_STAGES 8

/* SYMPTOM: one of the eight reducer stages' step_us_ewma() (the existing,
 *   already-measured EWMA of per-step wall time — platform/modules/util/src/stage.c)
 *   exceeds its effective budget. The budget is env ZCL_STAGE_BUDGET_US_<N>
 *   (uppercase stage name: HEADER_ADMIT, VALIDATE_HEADERS, BODY_FETCH,
 *   BODY_PERSIST, SCRIPT_VALIDATE, PROOF_VALIDATE, UTXO_APPLY, TIP_FINALIZE)
 *   when set, else a WARM-UP ROLLING BASELINE: the first
 *   STAGE_BUDGET_WARMUP_TICKS consecutive nonzero-EWMA detect() ticks lock a
 *   per-stage baseline, and the budget becomes
 *   baseline * STAGE_BUDGET_MULTIPLIER (floored at STAGE_BUDGET_FLOOR_US).
 *   The baseline approach means the budget is proportional to what THIS
 *   machine actually measures for THIS stage — a fast stage (header_admit,
 *   microseconds) and a slow one (proof_validate, Groth16 verification,
 *   milliseconds) each get their own realistic ceiling instead of one
 *   hand-tuned global constant. The multiplier is generous by design (a
 *   healthy node's own step-time jitter, already EWMA-smoothed with
 *   alpha=1/16, sits nowhere near it) so this never false-fires under normal
 *   load; only a genuine multi-x regression trips it.
 * REMEDY: OBSERVATIONAL ONLY — there is no repair seam this condition may
 *   use (that would risk touching the fold/validity path, which is
 *   forbidden). It names the worst-over-budget stage with a typed
 *   BLOCKER_TRANSIENT blocker ("stage_step_budget_exceeded") carrying the
 *   stage name, observed_ewma_us, and budget_us, and logs it.
 *   COND_REMEDY_FAILED is the honest "cannot/will-not auto-fix" outcome —
 *   mirrors reducer_drive_watchdog.
 * WITNESSED: clears the instant that SAME stage's live EWMA falls back to or
 *   under its budget (re-read fresh, not cached).
 * COND_WARN (a slow stage is not a fold failure); poll_secs=15 while
 *   inactive (backoff 60s, max_attempts=1 → operator_needed fast, honest
 *   "cannot fix"); cooldown re-arms every 600s, unbounded, while the
 *   regression persists, so a long slow patch re-notifies without
 *   permanently latching. */
void register_stage_step_budget_exceeded(void);

struct json_value;

#ifdef ZCL_TESTING
void stage_step_budget_exceeded_test_reset(void);
int  stage_step_budget_exceeded_test_remedy_calls(void);

/* Force stage `idx` (0..STAGE_BUDGET_NUM_STAGES-1, pipeline order: 0
 * header_admit, 1 validate_headers, 2 body_fetch, 3 body_persist,
 * 4 script_validate, 5 proof_validate, 6 utxo_apply, 7 tip_finalize) to
 * report `us` from its EWMA reader instead of calling the real
 * *_stage_step_us_ewma() accessor. -1 = use the real reader. */
void stage_step_budget_exceeded_test_set_ewma_us(int idx, int64_t us);

/* Force stage `idx`'s effective budget instead of the env/baseline lookup
 * (bypasses the warm-up entirely, so a test can trip a breach on the very
 * first tick). -1 = use the real env-or-baseline lookup. */
void stage_step_budget_exceeded_test_set_budget_us(int idx, int64_t us);
#endif

#endif /* ZCL_CONDITIONS_STAGE_STEP_BUDGET_EXCEEDED_H */
