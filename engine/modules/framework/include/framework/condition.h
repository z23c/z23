/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_FRAMEWORK_CONDITION_H
#define ZCL_FRAMEWORK_CONDITION_H

#include "json/json.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#define CONDITION_MAX_NAME 64
#define CONDITION_MAX_REGISTRY 64

enum condition_severity {
    COND_INFO = 0,
    COND_WARN,
    COND_CRITICAL,
};

enum condition_remedy_result {
    COND_REMEDY_OK = 0,
    COND_REMEDY_FAILED,
    COND_REMEDY_SKIP,
    /* Engine-only synthetic outcome: a remedy returned COND_REMEDY_OK but
     * the condition's witness did NOT confirm the symptom cleared within
     * witness_window_secs. Doctrine: "A remedy that returns ok must resolve
     * the symptom." The engine downgrades an un-witnessed remedy to this so
     * node.log never shows result=ok for a symptom that persists. A remedy
     * function MUST NOT return this value itself. */
    COND_REMEDY_UNWITNESSED,
};

typedef bool (*condition_detect_fn)(void);
typedef enum condition_remedy_result (*condition_remedy_fn)(void);
typedef bool (*condition_witness_fn)(int64_t target_at_detect);
/* TL-1: optional REFRESH-ONLY progress signal (see struct condition.progressing
 * below). Same argument convention as condition_witness_fn (the engine passes
 * the at-detect target). */
typedef bool (*condition_progressing_fn)(int64_t target_at_detect);
/* Optional REMEDY-URGENCY signal (see struct condition.urgent below). Takes no
 * argument — it reports only whether a time-sensitive input is ready NOW. */
typedef bool (*condition_urgent_fn)(void);
typedef bool (*condition_detail_fn)(struct json_value *out);

struct condition_state {
    _Atomic int64_t first_detect_unix;
    _Atomic int64_t last_poll_unix;
    _Atomic int64_t last_remedy_unix;
    _Atomic int64_t last_operator_needed_unix;
    _Atomic int64_t target_at_detect;
    _Atomic int attempts;
    _Atomic int last_outcome;
    _Atomic bool currently_active;
    _Atomic bool operator_needed_emitted;
    _Atomic int cleared_count;
    /* Continue-with-cooldown tier (sticky-node plan #7). For an
     * external-resource-dependent condition (peers/oracle absent), giving
     * up forever at max_attempts is a human dead-end on a RECOVERABLE class.
     * When cooldown_secs > 0 the engine re-arms the remedy after that long
     * backoff instead of latching: last_cooldown_unix gates the re-arm gap,
     * cooldown_rearms counts re-arms in the current fault episode, and
     * cooldown_episode_key is the fault identity at the last re-arm. A change
     * in fault identity (the condition's target_at_detect moved) starts a
     * fresh budget, exactly like chain_tip_watchdog.c's episode keying. */
    _Atomic int64_t last_cooldown_unix;
    _Atomic int cooldown_rearms;
    _Atomic int64_t cooldown_episode_key;
};

struct condition {
    const char *name;
    enum condition_severity severity;
    int poll_secs;
    int backoff_secs;
    int max_attempts;
    /* Continue-with-cooldown (sticky-node plan #7). 0 = legacy behavior:
     * latch permanently at max_attempts (correct for a genuinely-local,
     * deterministic-unrecoverable condition). > 0 = after max_attempts the
     * engine re-arms the remedy every cooldown_secs (a long 5-15 min backoff)
     * so an external-resource stall (peers/oracle) never permanently gives
     * up. cooldown_max_rearms bounds re-arms within ONE fault episode (a
     * continuous active span with an unchanged fault identity); 0 = unbounded
     * (the right default for a purely-transient external dependency). The
     * operator page still fires once per episode at max_attempts so a human
     * is informed, but the node keeps trying to self-heal. */
    int cooldown_secs;
    int cooldown_max_rearms;
    condition_detect_fn detect;
    condition_remedy_fn remedy;
    condition_witness_fn witness;
    /* TL-1: optional REFRESH-ONLY progress signal. After a remedy runs and the
     * witness has NOT cleared, the engine consults this (if non-NULL): a true
     * return means the remedy is making durable, resumable progress toward a
     * future witnessed success that has not yet landed (e.g. a chunked backfill
     * spanning MORE rounds than max_attempts), so the engine RESETS the attempt
     * budget to 0 — WITHOUT clearing (currently_active and cleared_count are
     * untouched; only the witness clears). NULL = legacy behavior: the budget
     * only ever resets on a witnessed clear, so a deterministic-unrecoverable
     * local fault still latches/pages exactly as before. Contract: the callback
     * MUST re-snapshot its own delta baseline on a true return so the next round
     * measures FRESH progress; pure churn (records frozen, no durable advance)
     * MUST return false so the budget still exhausts and the operator is paged
     * in bounded time. This is NEVER a clear-edge — it cannot mask a genuinely
     * stuck node, only keep a converging repair from false-paging. */
    condition_progressing_fn progressing;
    /* Optional REMEDY-URGENCY hook. When non-NULL and it returns true, the
     * remedy is treated as immediately due — the engine bypasses backoff_secs
     * for this tick (still gated by the max_attempts cap + cooldown re-arm, so
     * it can never spin past the attempt budget). Purpose: a time-sensitive
     * input has landed (e.g. a captured checkpoint header awaiting consume) and
     * should be processed on the next tick rather than after the full backoff.
     * Must be cheap and side-effect-free (a relaxed atomic read). NULL = legacy
     * backoff-only cadence. */
    condition_urgent_fn urgent;
    condition_detail_fn detail;
    int witness_window_secs;
    struct condition_state state;
};

struct condition_runtime_snapshot {
    bool registered;
    enum condition_severity severity;
    int poll_secs;
    int backoff_secs;
    int max_attempts;
    int witness_window_secs;
    bool currently_active;
    bool operator_needed_emitted;
    int attempts;
    int last_outcome;
    int cleared_count;
    /* Continue-with-cooldown registration (see struct condition above): 0
     * means the legacy permanent-latch behavior at max_attempts. Exposed so
     * tests (and any future registry audit) can assert a condition's
     * cooldown posture directly instead of only inferring it behaviorally. */
    int cooldown_secs;
    int cooldown_max_rearms;
};

struct main_state;

bool condition_register(const struct condition *cond);
bool condition_engine_has_registered(const char *name);
bool condition_engine_get_registered_snapshot(
    const char *name, struct condition_runtime_snapshot *out);
void condition_engine_tick(void);

/* Per-condition progress hook. Invoked by condition_engine_tick() once after
 * each condition's tick, on the SAME thread that drives the engine. Its sole
 * purpose is fine-grained liveness: the dedicated condition-runner thread
 * (engine/supervisors/src/self_heal.c) registers a hook that refreshes its
 * supervisor heartbeat, so a long multi-condition pass keeps beating between
 * conditions and only a single remedy that never returns can lapse the
 * runner's stall deadline. Must be cheap and non-blocking (an atomic store).
 * NULL clears it. Cleared by condition_engine_reset_for_testing(). */
void condition_engine_set_progress_hook(void (*fn)(void));

bool condition_engine_dump_state_json(struct json_value *out, const char *key);

struct condition_engine_summary {
    int registered_count;
    int active_count;
    int unresolved_count;
    int unresolved_critical_count;
};

/* One registry-lock pass over the verdict-critical condition counts. */
void condition_engine_get_summary(struct condition_engine_summary *out);
int condition_engine_get_active_count(void);
/* Count active episodes that have reached operator-needed state. This includes
 * max-attempt exhaustion and age-budget pages whose attempts remain below max. */
int condition_engine_get_unresolved_count(void);

/* Same predicate, scoped to COND_CRITICAL severity. Use this (not the
 * unscoped count above) to gate a broad/heavy remedy — a WARN-severity
 * condition may legitimately stay "unresolved" for a long time under its own
 * bounded, self-contained cooldown (e.g. an external peer/bandwidth fault)
 * without that ever meaning "run the chain-recovery ladder". */
int condition_engine_get_unresolved_critical_count(void);

/* Re-baseline the engine's wall-keyed cadence anchors (last_poll/last_remedy)
 * to "now" for every registered condition. Called by the clock_skew_reconcile
 * remedy after a wall-clock STEP so a backward jump cannot freeze backoff math
 * and a forward jump cannot fire every condition at once. Idempotent and
 * lock-safe; harmless to call when no skew occurred. */
void condition_engine_rebaseline_clocks(void);

void condition_engine_set_main_state(struct main_state *ms);
struct main_state *condition_engine_main_state(void);

const char *condition_severity_name(enum condition_severity s);
const char *condition_remedy_result_name(enum condition_remedy_result r);

#ifdef ZCL_TESTING
void condition_engine_reset_for_testing(void);

/* Zero the shared per-condition state atoms that every *_test_reset() must
 * clear between tests: attempts, last_outcome (-> COND_REMEDY_SKIP),
 * currently_active, operator_needed_emitted. Module-static detect/remedy
 * bookkeeping is each condition's own responsibility. */
void condition_reset_state(struct condition *c);
#endif

#endif /* ZCL_FRAMEWORK_CONDITION_H */
