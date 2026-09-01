/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/reducer_frontier_reconcile_light.h"
#include "reducer_frontier_light_observe.h"

#include "platform/time_compat.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_repair_coin_backfill.h"
#include "net/connman.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>

#define RFRL_COND_NAME "reducer_frontier_reconcile_light"

/* Peer-gate visibility memo. detect runs only on the serial condition-engine
 * tick thread; the active bit lives in the observability helper because
 * diagnostics can read it. The gate-suppress WARN is the shared log_throttle
 * de-storm primitive, keyed on a single "active" token:
 * log_throttle_reset() re-arms it when the suppression
 * ends (so the next engagement emits immediately, reps=0), and a same-key
 * keep-alive fires every 300 s carrying the suppressed-tick count. */
#define GATE_SUPPRESS_ACTIVE_KEY ((uint64_t)1)
static struct log_throttle g_gate_suppress = LOG_THROTTLE_INIT;
/* Emitted-WARN count for the gate-suppressed-actionable-detect path (only the
 * throttle-passed emissions, not every suppressed tick). Serial condition-
 * engine tick thread only, same as the throttle above. Test-visible via the
 * src-private hook at the bottom of this file. */
static int g_gate_suppress_warn_total;

/* Shared de-storm gate for the remedy-path refusal/repaired WARNs below: each
 * one persists identically across retries on a wedged node, so each gets its
 * own log_throttle keyed on the fields that change with genuine progress. */
static bool rfrl_throttle_emit(struct log_throttle *t, uint64_t key,
                               uint64_t *out_reps)
{
    return log_throttle_should_emit(t, key, platform_time_wall_unix(), 60,
                                    out_reps);
}

#ifdef ZCL_TESTING
/* Test-only post-remedy hook: simulates the TIPFIN backfill bumping its
 * tipfin_backfill.progress record DURING the remedy (the production writer
 * lives in the TIPFIN package; this Condition only snapshots/witnesses the
 * record). Lets the T10 harness prove the witness channel through the real
 * engine without that package. */
static void (*g_test_post_remedy_hook)(void);
#endif

/* FIX-1 progressing high-water baselines. The witness is the SOLE clear
 * predicate; progressing() only REFRESHES the attempt budget, and only on
 * FORWARD progress a rewind cannot fake: H* (a monotonic frontier) climbing, or
 * a coin/tipfin backfill record reaching a strictly NEW height above the
 * high-water mark. Seeded at the detect rising edge and raised (never lowered)
 * on a true progressing return, so a same-height rewind->re-derive churn no
 * longer refreshes forever — the budget exhausts, the operator pages, and the
 * sticky escalator arms. Serial condition-engine tick thread only (same as the
 * gate-suppress counter above); the -1 "absent" sentinel never lowers a mark. */
static _Atomic int g_progressing_hstar_hwm = -1;
static _Atomic int g_progressing_coin_next_hwm = -1;
static _Atomic int g_progressing_tipfin_hwm = -1;

static void rfrl_progressing_raise_hwm(int hstar, int coin_next, int tipfin)
{
    if (hstar > atomic_load(&g_progressing_hstar_hwm))
        atomic_store(&g_progressing_hstar_hwm, hstar);
    if (coin_next > atomic_load(&g_progressing_coin_next_hwm))
        atomic_store(&g_progressing_coin_next_hwm, coin_next);
    if (tipfin > atomic_load(&g_progressing_tipfin_hwm))
        atomic_store(&g_progressing_tipfin_hwm, tipfin);
}

static bool coin_backfill_refused_reconcile(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    if (!rr || !rr->coin_backfill_attempted)
        return false;
    return rr->coin_backfill_status != COIN_BACKFILL_NOT_APPLICABLE &&
           rr->coin_backfill_status != COIN_BACKFILL_SCANNING &&
           rr->coin_backfill_status != COIN_BACKFILL_REPAIRED &&
           rr->coin_backfill_status != COIN_BACKFILL_OWNER_REFUSED;
}

static bool peer_lag_allows_repair(struct main_state *ms, int hstar)
{
    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return true;

    /* F6: gate on how far the PROVABLE tip (H*) lags a peer, NOT the DOWNLOAD
     * tip (active_chain_height). When the fold is stalled below the header tip
     * — the common wedge — active_chain_height already sits at/above the peers'
     * static handshake starting_height, so the download-tip comparison
     * suppressed the repair exactly when it was needed. H* is the height the
     * repair is trying to lift, so it is the right lag to gate on. Fall back to
     * the download tip only when H* is unavailable. */
    int local = hstar >= 0
                    ? hstar
                    : (ms ? active_chain_height(&ms->chain_active) : -1);
    if (local < 0)
        return false;

    int peer_max = connman_max_peer_height(cm);
    if (peer_max > local)
        return true;

    /* A zero-peer copy still needs the local flag/cursor repair so it can hold
     * in repairing state and resume when a body source appears. Non-zero peers
     * that are not ahead are not useful evidence of a stale local tip. */
    return connman_get_node_count(cm) == 0;
}

/* Peer-gate BYPASS for a pending refused_coin_tear: the gate's
 * purpose — refusing repairs without peer-staleness evidence — does not
 * apply here, because coins_applied_height sitting above H*+1 is durable
 * internal-store evidence of damage, independent of any peer's height
 * (guards against the peer gate silently idling). Transition-logged: one WARN
 * when the bypass engages, re-armed when the tear state ends. */
static void note_peer_gate_bypass(
    const struct stage_reducer_frontier_reconcile_result *rr,
    const char *reason)
{
    if (rfrl_tear_bypass_active())
        return;
    rfrl_set_tear_bypass_active(true);
    rfrl_increment_tear_bypass_warn_total();
    LOG_WARN("condition",
             "[condition:reducer_frontier_reconcile_light] peer-gate BYPASS: "
             "%s (coins_applied_height=%d hstar=%d noncanonical_found=%d "
             "validate_refill_hole=%d body_persist_refill_hole=%d "
             "script_refill_hole=%d proof_refill_hole=%d) — "
             "durable internal-state damage is peer-independent evidence, "
             "detect proceeds with no peer ahead",
             reason, rr->coins_applied_height, rr->hstar,
             rr->noncanonical_found,
             rr->lowest_validate_headers_refill_hole,
             rr->lowest_body_persist_refill_hole,
             rr->lowest_script_validate_refill_hole,
             rr->lowest_proof_validate_refill_hole);
}

/* True when the dry-run reports any refusal/backfill-pending signal, or a
 * backfill progress record (coin or tipfin) is live on disk. Used only to
 * decide whether a gate suppression must be LOUD. */
static bool repair_evidence_pending(
    sqlite3 *db,
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    if (stage_reducer_frontier_result_has_gate_loudness_evidence(rr))
        return true;

    bool present = false;
    int v = -1;
    if (rfrl_read_coin_backfill_scan_cursor(db, &present, &v) && present)
        return true;
    if (rfrl_read_tipfin_backfill_progress(db, &present, &v) && present)
        return true;
    return false;
}

/* The peer gate can suppress an actionable detect, silently idling the whole
 * L1 layer; this logging keeps such suppressions visible. Stay quiet only for
 * the plain cursor-churn class with no other repair evidence (the gate's
 * intended job); otherwise WARN on the transition plus a 300 s keep-alive
 * carrying the suppressed-tick count (storm-safe: first occurrence never
 * suppressed). */
static void note_gate_suppressed(
    sqlite3 *db,
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    if (!repair_evidence_pending(db, rr)) {
        log_throttle_reset(&g_gate_suppress);
        return;
    }
    int64_t now = platform_time_wall_unix();
    uint64_t reps = 0;
    if (!log_throttle_should_emit(&g_gate_suppress, GATE_SUPPRESS_ACTIVE_KEY,
                                  now, 300, &reps))
        return;
    g_gate_suppress_warn_total++;
    LOG_WARN("condition",
             "[condition:reducer_frontier_reconcile_light] peer gate "
             "suppressed an actionable detect (repaired=%d "
             "vo_owner_refused=%d vo_attempted=%d cb_owner_refused=%d "
             "cb_attempted=%d stale_script_attempted=%d "
             "bf_refill_hole=%d script_refill_hole=%d "
             "proof_refill_hole=%d) while "
             "repair/backfill evidence is pending and no peer is ahead "
             "(suppressed_ticks=%llu)",
             rr->repaired, rr->value_overflow_repair_owner_refused,
             rr->value_overflow_repair_attempted,
             rr->coin_backfill_owner_refused, rr->coin_backfill_attempted,
             rr->stale_script_repair_attempted,
             rr->lowest_body_fetch_refill_hole,
             rr->lowest_script_validate_refill_hole,
             rr->lowest_proof_validate_refill_hole,
             (unsigned long long)reps);
}

static bool detect_reducer_frontier_reconcile_light(void)
{
    /* SUSPENDED during a from-genesis staged refold (jobs/refold_progress.h):
     * this self-repair drags below-anchor cursors back UP to the trusted
     * anchor, which is exactly what a refold must NOT do — the fold is
     * legitimately re-walking the frozen prefix from genesis. With the floor
     * lowered to 0 the L0 frontier reports the true folded height; this gate
     * stops L1 from fighting it. The condition is GATED, not deleted — a
     * normal boot (refold_in_progress()==false) runs the standard L1 path.
     *
     * This serial condition-engine tick is also the off-the-drive owner of the
     * CLEAR edge: once the fold's utxo_apply cursor reaches/passes the clear
     * target, the matching clear helper drops the durable signal and the very
     * next tick falls through to the normal self-repair. (Both clear helpers are
     * cheap no-ops when not refolding or still below their target.)
     *
     * A from-ANCHOR refold (refold_from_anchor_active()) clears when the
     * fold's utxo_apply cursor reaches the durable RESUME TARGET (the tip it is
     * climbing to), NOT the trusted anchor (the fold STARTS at the anchor). A
     * from-genesis refold keeps the original anchor-crossing clear edge. */
    if (refold_in_progress()) {
        sqlite3 *db = progress_store_db();
        if (db) {
            int ua = -1;
            if (rfrl_read_reducer_cursor(db, "utxo_apply", &ua) && ua >= 0) {
                if (refold_from_anchor_active()) {
                    /* CUTOVER DEFECT 1 — the from-anchor resume target is
                     * captured ONCE at boot, but the chain advances during a
                     * multi-hour fold. Re-write the durable target to
                     * MAX(stored, live tip) BEFORE the clear so the clear edge
                     * keys on the CURRENT tip, not the frozen boot height —
                     * otherwise utxo_apply crossing the stale boot target
                     * un-suspends below-anchor self-repair while the fold is
                     * still climbing to the real tip (the re-wedge surface).
                     * Touches ONLY progress.kv — no csr->lock, no evidence
                     * machinery (lock-order-safe on the reducer-drive path). */
                    struct main_state *ms = sync_monitor_main_state();
                    if (ms) {
                        int live_tip =
                            active_chain_height(&ms->chain_active);
                        if (live_tip >= 0)
                            (void)refold_progress_bump_target(
                                db, (int32_t)live_tip);
                    }
                    (void)refold_progress_clear_if_reached(db, (int32_t)ua, -1);
                } else {
                    (void)refold_progress_clear_if_crossed(db, (int32_t)ua);
                }
            }
        }
        if (refold_in_progress())
            return false;
    }

    int64_t tip_age = sync_monitor_tip_advance_age();
    if (tip_age >= 0 && tip_age < 60)
        return false;

    sqlite3 *db = progress_store_db();
    struct main_state *ms = sync_monitor_main_state();
    if (!db || !ms)
        return false;

    /* The read-only dry-run runs BEFORE the peer gate so a durable
     * internal tear can bypass it. No new steady-state cost: it already ran
     * on every detect tick whenever a peer was ahead. */
    /* Steady-state dry-run result — "nothing to reconcile" on a healthy
     * tip, polled every 5s. Actionable findings below already log via
     * g_gate_suppress; logging here would storm node.log. */
    struct stage_reducer_frontier_reconcile_result rr;
    if (!stage_reducer_frontier_reconcile_light_needed(db, ms, &rr))
        return false; // raw-return-ok:steady-state-nothing-to-reconcile
    rfrl_snapshot_reconcile_result(RFRL_RR_PHASE_DETECT, &rr);
    if (rr.refused_coin_unknown)
        return false;
    if (stage_repair_tipfin_refusal_is_pending_forward(&rr)) {
        rfrl_set_tear_bypass_active(false);
        log_throttle_reset(&g_gate_suppress);
        return false;
    }
    if (!rr.refused_coin_tear && !rr.repaired &&
        !stage_reducer_frontier_result_has_gate_loudness_evidence(&rr)) {
        /* Nothing actionable: both transition memos re-arm.
         * noncanonical_found counts relabel/reorg-residue rows the
         * dry-run judged stale — the apply purge is the remedy.
         * reorg_residue_tipfin_found counts stale ok=0 reorg_detected
         * tip_finalize verdicts the apply path replaces in place. */
        rfrl_set_tear_bypass_active(false);
        log_throttle_reset(&g_gate_suppress);
        return false;
    }

    if (!peer_lag_allows_repair(ms, rr.hstar)) {
        if (rr.refused_coin_tear) {
            note_peer_gate_bypass(&rr, "refused_coin_tear pending");
        } else if (rr.noncanonical_found > 0) {
            /* Durable below-frontier damage — e.g. a validate/script
             * hash_split the noncanonical purge PROTECTED for the
             * coins-rewinding stale-script replay — is peer-independent
             * evidence exactly like refused_coin_tear: the fold tip H* is
             * pinned below the header tip with no peer ahead. BYPASS the gate
             * so the remedy runs and the episode stays active; WITHOUT this the
             * LIVE node (peers at the tip, none ahead) never arms the
             * sticky_escalator and the wedge is silent. */
            note_peer_gate_bypass(&rr, "noncanonical_found pending");
        } else if (rr.lowest_script_validate_refill_hole >= 0 ||
                   rr.lowest_proof_validate_refill_hole >= 0 ||
                   rr.lowest_validate_headers_refill_hole >= 0 ||
                   rr.lowest_body_persist_refill_hole >= 0) {
            /* A rowless stage-log hole below the stage cursor
             * (script_validate_log / proof_validate_log /
             * validate_headers_log / body_persist_log — e.g. the residue of a
             * noncanonical purge that deleted stale-hash rows without
             * clamping these cursors) is durable internal damage: the
             * canonical body is already persisted on disk, so the
             * re-derivation needs no peer. Gating this repair on "a peer is
             * ahead" — connman_max_peer_height reads the peers' STATIC
             * handshake starting_height (core/modules/net/src/connman.c), which near
             * tip is <= the local height forever — would suppress the only
             * healer for a rowless script_validate_log/proof_validate_log hole.
             * body_fetch refill holes stay gated (re-fetching a
             * body needs a peer to serve it); their suppression is LOUD
             * via note_gate_suppressed below. */
            note_peer_gate_bypass(&rr, "stage-log refill hole pending");
        } else if (rr.label_splice_rebind_lowest >= 0) {
            /* A NULL-block_hash proof/script suffix pinning utxo_apply on
             * label_splice is durable below-frontier internal damage: the
             * canonical bodies are already persisted, so re-deriving + re-stamping
             * block_hash needs no peer. Gating it on "a peer is ahead" would idle
             * the only healer for the pure label_splice wedge near tip (a
             * zero/behind-peer copy). Peer-independent, exactly like a stage-log
             * refill hole. */
            note_peer_gate_bypass(&rr, "label_splice re-bind pending");
        } else {
            /* Gate KEPT for the plain cursor-churn repair class: peers that
             * exist but are not ahead are no staleness evidence. The tear
             * state (if any) ended, so the bypass memo re-arms. */
            rfrl_set_tear_bypass_active(false);
            note_gate_suppressed(db, &rr);
            return false;
        }
    } else {
        rfrl_set_tear_bypass_active(false);
    }
    log_throttle_reset(&g_gate_suppress);

    /* never-stuck-invariant-3: capture the at-detect baseline ONCE, at the
     * RISING EDGE of an episode — NOT on every detect-true tick. detect() runs
     * before the engine flips currently_active, so on the first detect of a new
     * episode the registered snapshot still reads inactive. The old code
     * re-stamped g_hstar_at_detect = rr.hstar every tick: a sustained
     * detect-true episode that IS climbing H* one hole at a time would
     * re-baseline to the just-climbed H* each tick, so the witness's
     * `hstar_now > hstar_at_detect` never held — a genuinely-progressing repair
     * accrued attempts and false-paged. Capturing once lets any real H* climb
     * during the episode clear the witness. The coin/tipfin snapshots are the
     * progressing() delta baseline; they are likewise frozen at the rising edge
     * and refreshed ONLY by progressing() on a true return (REFRESH-only, never
     * a clear-edge). condition_engine_get_registered_snapshot takes the engine
     * mutex, which the tick path does NOT hold while calling detect(). */
    struct condition_runtime_snapshot snap;
    bool already_active =
        condition_engine_get_registered_snapshot(RFRL_COND_NAME, &snap) &&
        snap.currently_active;
    if (!already_active) {
        rfrl_detect_baseline_set(active_chain_height(&ms->chain_active),
                                 rr.hstar, rr.sweep_top);
        rfrl_snapshot_reducer_cursors(db);
        rfrl_snapshot_coin_backfill_scan(db);
        rfrl_snapshot_coin_backfill_insert_progress();
        rfrl_snapshot_tipfin_backfill(db);
        /* Seed the progressing high-water baselines from the rising-edge
         * frontier so a FROZEN backfill record never refreshes the budget while
         * a genuinely-advancing one does (FIX-1). raise_hwm ignores the -1
         * "absent" sentinel, so a record that appears later still counts. */
        rfrl_progressing_raise_hwm(rr.hstar,
                                   rfrl_coin_backfill_scan_next_at_detect(),
                                   rfrl_tipfin_backfill_progress_at_detect());
    }
    return true;
}

/* The operative cause the remedy reports on, in strict precedence order. Split
 * out (with rfrl_remedy_outcome below) so the outcome is a PURE function of the
 * reconcile result — directly testable, and the single source of truth the
 * remedy switch logs against. The label-splice re-bind deliberately outranks
 * every coin refusal: a fired re-bind is coins-untouching forward progress and
 * must never be masked by an unrelated coin_backfill refusal at a later height
 * (the conflation regression this precedence fixes). */
enum rfrl_remedy_cause {
    RFRL_CAUSE_REPAIRED_OR_SKIP = 0, /* outcome derives from rr.repaired */
    RFRL_CAUSE_COIN_UNKNOWN,
    RFRL_CAUSE_TIPFIN_PENDING,
    RFRL_CAUSE_LABEL_SPLICE_REBOUND,
    RFRL_CAUSE_COIN_TEAR,
    RFRL_CAUSE_VALUE_OVERFLOW_REFUSED,
    RFRL_CAUSE_COIN_BACKFILL_OWNER_REFUSED,
    RFRL_CAUSE_COIN_BACKFILL_REFUSED,
    RFRL_CAUSE_STALE_SCRIPT_INVALID,
};

static enum rfrl_remedy_cause rfrl_remedy_classify(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    if (rr->refused_coin_unknown)
        return RFRL_CAUSE_COIN_UNKNOWN;
    if (stage_repair_tipfin_refusal_is_pending_forward(rr))
        return RFRL_CAUSE_TIPFIN_PENDING;
    /* Conflation fix: a fired label-splice re-bind outranks any coin refusal. */
    if (rr->label_splice_rebound > 0)
        return RFRL_CAUSE_LABEL_SPLICE_REBOUND;
    if (rr->refused_coin_tear)
        return RFRL_CAUSE_COIN_TEAR;
    if (rr->value_overflow_repair_owner_refused)
        return RFRL_CAUSE_VALUE_OVERFLOW_REFUSED;
    if (rr->coin_backfill_owner_refused)
        return RFRL_CAUSE_COIN_BACKFILL_OWNER_REFUSED;
    if (coin_backfill_refused_reconcile(rr))
        return RFRL_CAUSE_COIN_BACKFILL_REFUSED;
    if (rr->stale_script_repair_genuinely_invalid)
        return RFRL_CAUSE_STALE_SCRIPT_INVALID;
    return RFRL_CAUSE_REPAIRED_OR_SKIP;
}

static enum condition_remedy_result rfrl_remedy_outcome(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    switch (rfrl_remedy_classify(rr)) {
    case RFRL_CAUSE_COIN_UNKNOWN:
    case RFRL_CAUSE_TIPFIN_PENDING:
        return COND_REMEDY_SKIP;
    case RFRL_CAUSE_LABEL_SPLICE_REBOUND:
        return COND_REMEDY_OK;
    case RFRL_CAUSE_COIN_TEAR:
    case RFRL_CAUSE_VALUE_OVERFLOW_REFUSED:
    case RFRL_CAUSE_COIN_BACKFILL_OWNER_REFUSED:
    case RFRL_CAUSE_COIN_BACKFILL_REFUSED:
    case RFRL_CAUSE_STALE_SCRIPT_INVALID:
        return COND_REMEDY_FAILED;
    case RFRL_CAUSE_REPAIRED_OR_SKIP:
    default:
        return rr->repaired ? COND_REMEDY_OK : COND_REMEDY_SKIP;
    }
}

static enum condition_remedy_result remedy_reducer_frontier_reconcile_light(void)
{
    /* detect() suspends during a staged refold, but the condition engine
     * keeps remedying an ACTIVE episode even when detect() reads false
     * (limbo fix in engine/modules/framework/src/condition.c), so the remedy needs the
     * same guard: the apply pass would drag below-anchor cursors back up
     * and fight the in-progress fold. The fold IS the recovery work. */
    if (refold_in_progress())
        return COND_REMEDY_SKIP;

    sqlite3 *db = progress_store_db();
    struct main_state *ms = sync_monitor_main_state();
    if (!db || !ms)
        return COND_REMEDY_SKIP;

    /* Reclaim settled repair markers below the retention margin (best-effort). */
    if (repair_marker_gc_settled(db, reducer_frontier_provable_tip_cached()) < 0)
        LOG_WARN("condition", "[condition:reducer_frontier_reconcile_light] "
                 "repair_marker GC failed");

    rfrl_increment_remedy_calls();
#ifdef ZCL_TESTING
    /* Stands in for the TIPFIN backfill's in-remedy progress-record bump
     * (see the hook's declaration comment). */
    if (g_test_post_remedy_hook)
        g_test_post_remedy_hook();
#endif

    struct stage_reducer_frontier_reconcile_result rr;
    if (!stage_reducer_frontier_reconcile_light(db, ms, &rr))
        return COND_REMEDY_FAILED;
    rfrl_snapshot_reconcile_result(RFRL_RR_PHASE_REMEDY, &rr);

    /* One classification drives BOTH the observability WARN and the returned
     * outcome (rfrl_remedy_outcome is the single source of truth). The cases
     * are in strict precedence order; label-splice re-bind outranks the coin
     * refusals below it so a successful re-bind is never masked. */
    switch (rfrl_remedy_classify(&rr)) {
    case RFRL_CAUSE_COIN_UNKNOWN: {
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        if (rfrl_throttle_emit(&t, 1, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] refused "
                     "coins_applied_height absent repeats=%llu",
                     (unsigned long long)reps);
        return COND_REMEDY_SKIP;
    }
    case RFRL_CAUSE_TIPFIN_PENDING: {
        /* Keyed on refused height + coins_applied/hstar/reason so a moving
         * refusal re-emits but a stuck one collapses to keepalive. */
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t key =
            ((uint64_t)(uint32_t)rr.tipfin_backfill_refused_height << 32) |
            (uint32_t)(((uint32_t)rr.coins_applied_height << 16) ^
                       ((uint32_t)rr.hstar << 8) ^
                       ((uint32_t)rr.tipfin_backfill_refused_reason << 4) ^
                       (uint32_t)rr.tipfin_backfill_refused_log);
        uint64_t reps = 0;
        if (rfrl_throttle_emit(&t, key, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] pending "
                     "tipfin backfill reason=%s binding_log=%s h=%d "
                     "coins_applied=%d hstar=%d repeats=%llu",
                     stage_repair_tipfin_refused_reason_label(
                         rr.tipfin_backfill_refused_reason),
                     stage_repair_tipfin_refused_log_label(
                         rr.tipfin_backfill_refused_log),
                     rr.tipfin_backfill_refused_height,
                     rr.coins_applied_height, rr.hstar,
                     (unsigned long long)reps);
        return COND_REMEDY_SKIP;
    }
    case RFRL_CAUSE_LABEL_SPLICE_REBOUND: {
        /* Coins-untouching forward progress: report success independent of any
         * coin_backfill refusal at a later height (the conflation regression).
         * Keyed on (hstar, lowest, rebound count) so a genuinely-advancing
         * re-bind re-emits but a stuck repeat collapses to keepalive. */
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t key =
            ((uint64_t)(uint32_t)rr.hstar << 32) |
            (uint32_t)(((uint32_t)rr.label_splice_rebind_lowest << 4) ^
                       (uint32_t)rr.label_splice_rebound);
        uint64_t reps = 0;
        if (rfrl_throttle_emit(&t, key, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] label_splice "
                     "RE-BOUND hstar=%d lowest_null=%d cursors_rewound=%d "
                     "deleted_null_rows=%lld coin_backfill_status=%d "
                     "(re-bind is progress regardless of any coin refusal) "
                     "repeats=%llu",
                     rr.hstar, rr.label_splice_rebind_lowest,
                     rr.label_splice_rebound,
                     (long long)rr.label_splice_deleted_rows,
                     rr.coin_backfill_status, (unsigned long long)reps);
        return COND_REMEDY_OK;
    }
    case RFRL_CAUSE_COIN_TEAR: {
        /* Keyed on (coins_applied_height, hstar), mirroring
         * stage_repair_reducer_frontier.c's l1_refuse_throttle. */
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t key = ((uint64_t)(uint32_t)rr.coins_applied_height << 32) |
                       (uint32_t)rr.hstar;
        uint64_t reps = 0;
        if (rfrl_throttle_emit(&t, key, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] refused "
                     "coins_applied_height=%d hstar=%d repeats=%llu",
                     rr.coins_applied_height, rr.hstar,
                     (unsigned long long)reps);
        return COND_REMEDY_FAILED;
    }
    case RFRL_CAUSE_VALUE_OVERFLOW_REFUSED: {
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t reps = 0, h = (uint64_t)(uint32_t)rr.value_overflow_repair_height;
        if (rfrl_throttle_emit(&t, h, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] refused "
                     "value_overflow repair h=%d: owner ack missing "
                     "repeats=%llu",
                     rr.value_overflow_repair_height,
                     (unsigned long long)reps);
        return COND_REMEDY_FAILED;
    }
    /* Belt-and-suspenders engine accounting: the backfill Job pages the
     * operator directly on every refusal status; never delete — coin_backfill
     * owner-ack env gate — this surfacing must never be the paging path. */
    case RFRL_CAUSE_COIN_BACKFILL_OWNER_REFUSED: {
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t reps = 0, h = (uint64_t)(uint32_t)rr.coin_backfill_hole_height;
        if (rfrl_throttle_emit(&t, h, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] refused "
                     "coin backfill h=%d: owner ack missing repeats=%llu",
                     rr.coin_backfill_hole_height,
                     (unsigned long long)reps);
        return COND_REMEDY_FAILED;
    }
    case RFRL_CAUSE_COIN_BACKFILL_REFUSED: {
        /* Keyed on hole height + status/unresolved/inserted/scan_next. */
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t key =
            ((uint64_t)(uint32_t)rr.coin_backfill_hole_height << 32) |
            (uint32_t)(((uint32_t)rr.coin_backfill_status << 24) ^
                       ((uint32_t)rr.coin_backfill_unresolved << 16) ^
                       ((uint32_t)rr.coin_backfill_inserted << 8) ^
                       (uint32_t)rr.coin_backfill_scan_next);
        uint64_t reps = 0;
        if (rfrl_throttle_emit(&t, key, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] refused "
                     "coin backfill h=%d status=%s unresolved=%d inserted=%d "
                     "scan_next=%d repeats=%llu",
                     rr.coin_backfill_hole_height,
                     rfrl_coin_backfill_status_label(rr.coin_backfill_status),
                     rr.coin_backfill_unresolved, rr.coin_backfill_inserted,
                     rr.coin_backfill_scan_next, (unsigned long long)reps);
        return COND_REMEDY_FAILED;
    }
    case RFRL_CAUSE_STALE_SCRIPT_INVALID: {
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t reps = 0, h = (uint64_t)(uint32_t)rr.stale_script_repair_height;
        if (rfrl_throttle_emit(&t, h, &reps))
            LOG_WARN("condition",
                     "[condition:reducer_frontier_reconcile_light] refused "
                     "stale script replay h=%d: dry-run still invalid "
                     "repeats=%llu",
                     rr.stale_script_repair_height,
                     (unsigned long long)reps);
        return COND_REMEDY_FAILED;
    }
    case RFRL_CAUSE_REPAIRED_OR_SKIP:
    default:
        break;
    }

    if (!rr.repaired)
        return COND_REMEDY_SKIP;

    /* A wedged node can re-derive the SAME clamp every remedy retry — key
     * on hstar + coins_applied_height + the mutation counts, mirroring
     * stage_repair_reducer_frontier.c's l1_repaired_throttle, so genuine
     * forward progress still re-emits. */
    static struct log_throttle repaired_throttle = LOG_THROTTLE_INIT;
    uint64_t repaired_key =
        ((uint64_t)(uint32_t)rr.hstar << 32) |
        (uint32_t)(((uint32_t)rr.coins_applied_height << 12) ^
                   (uint32_t)(rr.have_data_cleared + rr.failed_mask_cleared +
                              rr.have_data_set + rr.scripts_set));
    uint64_t repaired_reps = 0;
    if (rfrl_throttle_emit(&repaired_throttle, repaired_key, &repaired_reps))
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] hstar=%d "
                 "coins_applied=%d sweep_top=%d validate_headers=%d->%d "
                 "body_fetch=%d->%d body_persist=%d->%d "
                 "script_validate=%d->%d proof_validate=%d->%d "
                 "tip_finalize=%d->%d scripts_set=%d have_data_set=%d "
                 "have_data_cleared=%d validate_hash_split=%d "
                 "script_hash_split=%d script_refill_hole=%d "
                 "proof_refill_hole=%d failed_mask_cleared=%d repeats=%llu",
                 rr.hstar, rr.coins_applied_height, rr.sweep_top,
                 rr.validate_headers_cursor_before,
                 rr.validate_headers_cursor_after,
                 rr.body_fetch_cursor_before, rr.body_fetch_cursor_after,
                 rr.body_persist_cursor_before, rr.body_persist_cursor_after,
                 rr.script_validate_cursor_before,
                 rr.script_validate_cursor_after,
                 rr.proof_validate_cursor_before,
                 rr.proof_validate_cursor_after,
                 rr.tip_finalize_cursor_before, rr.tip_finalize_cursor_after,
                 rr.scripts_set, rr.have_data_set, rr.have_data_cleared,
                 rr.lowest_validate_headers_hash_split,
                 rr.lowest_script_validate_hash_split,
                 rr.lowest_script_validate_refill_hole,
                 rr.lowest_proof_validate_refill_hole,
                 rr.failed_mask_cleared, (unsigned long long)repaired_reps);
    /* rr.repaired is true here (the !repaired SKIP above returned); route the
     * terminal outcome through the single source of truth so the switch and this
     * tail can never diverge. */
    return rfrl_remedy_outcome(&rr);
}

static bool witness_reducer_frontier_reconcile_light(int64_t target_at_detect)
{
    /* The engine passes a wall-clock TIMESTAMP here (condition.c stores `now`
     * into target_at_detect), NOT a height — ignore it and read our own
     * captured baseline. */
    (void)target_at_detect;

    /* SOLE success predicate: the durable reducer frontier H* advanced PAST
     * the H* captured at detect (g_hstar_at_detect, set in detect). H* =
     * reducer_frontier_compute_hstar = MIN over every stage's contiguous ok=1
     * prefix — the only height the node may serve as its tip.
     *
     * The old witness ALSO cleared the instant active_chain_height (the
     * DOWNLOAD/header tip) grew, OR any reducer cursor moved, OR a coin/tipfin
     * backfill record advanced. But the download tip climbs on EVERY new block
     * admitted to the index while the fold stays frozen one below it, so the
     * witness false-greened on essentially every ~5 s tick, reset attempts to
     * 0, and NEVER reached max_attempts — EV_OPERATOR_NEEDED / sticky_escalator
     * could not fire on a genuinely stuck node (the live 6244 silent loops).
     * Those proxy clear-edges are gone: only a real H* advance clears, so a
     * non-advancing remedy now leaves the witness false, accrues attempts,
     * trips max_attempts, and pages the operator in bounded time. A read
     * failure is "not yet cleared" (false), never a false clear. */
    int hstar_at_detect = rfrl_hstar_at_detect();
    if (hstar_at_detect < 0)
        return false;

    sqlite3 *db = progress_store_db();
    if (!db) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] witness: "
                 "progress db unavailable — treating as not-yet-cleared");
        return false;
    }

    progress_store_tx_lock();
    int32_t hstar_now = -1;
    int32_t served_floor = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar_now, &served_floor);
    progress_store_tx_unlock();
    if (!ok) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] witness: H* "
                 "recompute failed — treating as not-yet-cleared");
        return false;
    }
    return hstar_now > hstar_at_detect;
}

/* TL-1 REFRESH-ONLY progress signal. The H* witness above is the SOLE
 * clear/success predicate; this is consulted by the engine ONLY when the
 * witness is still false after a remedy, to decide whether the attempt budget
 * should be refreshed (a converging multi-round repair) rather than exhausted
 * (pure churn).
 *
 * FIX-1: refresh ONLY on forward progress a same-height rewind cannot fake —
 * H* (the monotonic provable frontier) climbing above its high-water baseline,
 * or a coin/tipfin backfill record reaching a strictly NEW height above its
 * high-water baseline — plus the edge-triggered coins-inserted signal (keyed on
 * the remedy call, so a stale nonzero cannot refresh forever). The old code
 * ALSO refreshed on any present<->absent record transition and re-baselined to
 * the CURRENT (possibly rewound-low) value, so a same-height rewind->re-derive
 * churn refreshed the budget forever: max_attempts was never reached, the
 * operator was never paged, and the sticky escalator never armed. The baselines
 * are HIGH-WATER (raised at detect + on a true return, never lowered) so a
 * rewind to a previously-seen height no longer refreshes; pure churn now
 * exhausts the budget in bounded time. These statics are NEVER a witness
 * clear-edge (only reducer_frontier_compute_hstar clears). */
static bool progressing_reducer_frontier_reconcile_light(
    int64_t target_at_detect)
{
    /* The engine passes the wall-clock target timestamp; we key on our own
     * high-water baselines, not on it. */
    (void)target_at_detect;

    sqlite3 *db = progress_store_db();
    if (!db) {
        LOG_WARN("condition",
                 "[condition:reducer_frontier_reconcile_light] progressing: "
                 "progress db unavailable — treating as no-progress");
        return false;
    }

    bool progressed = false;

    /* (1) H* — the provable frontier — advanced above its high-water baseline.
     * H* is monotonic; a same-height rewind cannot fake it. (Belt-and-
     * suspenders vs the witness, the sole CLEAR predicate: any climb past the
     * at-detect H* already clears there.) */
    int32_t hstar_now = -1;
    int32_t served_floor = -1;
    progress_store_tx_lock();
    bool have_hstar =
        reducer_frontier_compute_hstar(db, &hstar_now, &served_floor);
    progress_store_tx_unlock();
    if (have_hstar && hstar_now > atomic_load(&g_progressing_hstar_hwm))
        progressed = true;

    /* (2) coin_backfill resumable scan cursor reached a strictly NEW height
     * above its high-water baseline. A wide hole needs more chunks
     * (COIN_BACKFILL_SCAN_CHUNK_BLOCKS/call) than max_attempts; each chunk
     * advances scan_next durably before H* moves. */
    bool coin_present = false;
    int coin_next = -1;
    if (rfrl_read_coin_backfill_scan_cursor(db, &coin_present, &coin_next) &&
        coin_present &&
        coin_next > atomic_load(&g_progressing_coin_next_hwm))
        progressed = true;

    /* (3) tipfin backfill progress record reached a strictly NEW height above
     * its high-water baseline. */
    bool tip_present = false;
    int tip_progress = -1;
    if (rfrl_read_tipfin_backfill_progress(db, &tip_present, &tip_progress) &&
        tip_present &&
        tip_progress > atomic_load(&g_progressing_tipfin_hwm))
        progressed = true;

    /* (4) the most recent reconcile pass inserted coins after the current
     * progress baseline. The inserted count itself is a last-result field, not
     * a monotonically increasing cursor; key it to the remedy call that produced
     * that result so a stale nonzero value cannot refresh attempts forever. */
    int insert_remedy_call = rfrl_last_reconcile_remedy_call();
    if (rfrl_last_coin_backfill_inserted() > 0 &&
        insert_remedy_call >
            rfrl_coin_backfill_insert_remedy_call_at_detect())
        progressed = true;

    /* Re-baseline (high-water: raised, never lowered) on a true return so the
     * next round measures fresh forward progress. A false return leaves the
     * baselines untouched, so progress accrued over multiple rounds is still
     * detected. */
    if (progressed) {
        rfrl_progressing_raise_hwm(have_hstar ? hstar_now : -1,
                                   coin_present ? coin_next : -1,
                                   tip_present ? tip_progress : -1);
        rfrl_snapshot_coin_backfill_insert_progress();
    }
    return progressed;
}

static struct condition c_reducer_frontier_reconcile_light = {
    .name = RFRL_COND_NAME,
    .severity = COND_CRITICAL,
    .poll_secs = 5,
    .backoff_secs = 30,
    .max_attempts = 5,
    .detect = detect_reducer_frontier_reconcile_light,
    .remedy = remedy_reducer_frontier_reconcile_light,
    .witness = witness_reducer_frontier_reconcile_light,
    .progressing = progressing_reducer_frontier_reconcile_light,
    .detail = rfrl_detail_push,
    .witness_window_secs = 60,
};

void register_reducer_frontier_reconcile_light(void)
{
    (void)condition_register(&c_reducer_frontier_reconcile_light);
}

#ifdef ZCL_TESTING
void reducer_frontier_reconcile_light_test_reset(void)
{
    struct condition_state *s = &c_reducer_frontier_reconcile_light.state;
    rfrl_observe_reset_for_testing();
    log_throttle_reset(&g_gate_suppress);
    g_gate_suppress_warn_total = 0;
    atomic_store(&g_progressing_hstar_hwm, -1);
    atomic_store(&g_progressing_coin_next_hwm, -1);
    atomic_store(&g_progressing_tipfin_hwm, -1);
    g_test_post_remedy_hook = NULL;
    condition_reset_state(&c_reducer_frontier_reconcile_light);
    atomic_store(&s->last_remedy_unix, (int64_t)0);
    atomic_store(&s->last_operator_needed_unix, (int64_t)0);
}

void reducer_frontier_reconcile_light_test_clear_backoff(void);
void reducer_frontier_reconcile_light_test_clear_backoff(void)
{
    struct condition_state *s = &c_reducer_frontier_reconcile_light.state;
    atomic_store(&s->last_remedy_unix, (int64_t)0);
}

int reducer_frontier_reconcile_light_test_remedy_calls(void)
{
    return rfrl_remedy_calls();
}

/* Pure remedy-decision hook: exercises rfrl_remedy_outcome (the single source of
 * truth the remedy switch logs against) on a caller-constructed result. Lets the
 * conflation regression — a successful label_splice re-bind masked by an
 * unrelated coin_backfill refusal — be asserted directly without the engine. */
enum condition_remedy_result
reducer_frontier_reconcile_light_test_remedy_outcome(
    const struct stage_reducer_frontier_reconcile_result *rr);
enum condition_remedy_result
reducer_frontier_reconcile_light_test_remedy_outcome(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return rfrl_remedy_outcome(rr);
}

/* src-private test hooks (mirrored by test_reducer_reconcile_witness.c, the
 * test_utxo_apply_stage.c delta-internal pattern — not in the public
 * header). */
void reducer_frontier_reconcile_light_test_set_post_remedy_hook(
    void (*fn)(void));
void reducer_frontier_reconcile_light_test_set_post_remedy_hook(
    void (*fn)(void))
{
    g_test_post_remedy_hook = fn;
}

int reducer_frontier_reconcile_light_test_bypass_warns(void);
int reducer_frontier_reconcile_light_test_bypass_warns(void)
{
    return rfrl_tear_bypass_warn_total();
}

int reducer_frontier_reconcile_light_test_gate_suppress_warns(void);
int reducer_frontier_reconcile_light_test_gate_suppress_warns(void)
{
    return g_gate_suppress_warn_total;
}

bool reducer_frontier_reconcile_light_test_progressing(void);
bool reducer_frontier_reconcile_light_test_progressing(void)
{
    return progressing_reducer_frontier_reconcile_light(0);
}

void reducer_frontier_reconcile_light_test_snapshot_insert_baseline(void);
void reducer_frontier_reconcile_light_test_snapshot_insert_baseline(void)
{
    rfrl_snapshot_coin_backfill_insert_progress();
}

void reducer_frontier_reconcile_light_test_note_coin_insert_result(int inserted);
void reducer_frontier_reconcile_light_test_note_coin_insert_result(int inserted)
{
    rfrl_increment_remedy_calls();
    struct stage_reducer_frontier_reconcile_result rr = {0};
    rr.coin_backfill_inserted = inserted;
    rfrl_snapshot_reconcile_result(RFRL_RR_PHASE_REMEDY, &rr);
}
#endif
