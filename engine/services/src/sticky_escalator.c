/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sticky escalator — implementation. See services/sticky_escalator.h. */

// one-result-type-ok:escalator-no-fallible-surface
//
// This is a supervisor-child meta-condition, not a fallible service executor.
// Its public surfaces are void drivers/setters, a single coherent dump_state_json
// out-struct, and bool PREDICATES (armed / test accessors) — none strips a
// failure reason. Every rung dispatch logs + emits EV_RECOVERY_ACTION; the
// non-latching page emits EV_OPERATOR_NEEDED. No bare-bool lost-reason here.
//
// Every rung has a real in-process surface (no NOT_IMPLEMENTED stubs): a rung
// whose precondition is absent (no reachable anchor / verified rewind base)
// NAMES a typed DEPENDENCY blocker and returns FAILED so the ladder advances —
// it never fakes a "done". The deepest rung ALWAYS re-derives from folded bodies
// (from-anchor refold + self-respawn), NEVER installs a borrowed value.

#include "platform/time_compat.h"
#include "services/sticky_escalator.h"
#include "services/sticky_escalator_resnapshot.h"
#include "services/sticky_escalator_trigger.h"

#include "supervisors/domains.h"
#include "framework/condition.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/stage_repair.h"
#include "services/chain_tip_watchdog.h"
#include "services/sync_monitor.h"
#include "config/boot.h"
#include "config/runtime.h"
#include "net/connman.h"
#include "storage/boot_auto_reindex.h"
#include "storage/boot_auto_refold.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/supervisor.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "event/event.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
/* ── Module state ──────────────────────────────────────────────────── */

static struct main_state       *g_ms      = NULL;
static const char              *g_datadir = NULL;
static struct liveness_contract g_contract;
static _Atomic supervisor_child_id g_id = SUPERVISOR_INVALID_ID;

/* Ladder state. All atomic — note_stall runs off-thread (watchdog /
 * worker_on_stall) while drive() runs on the self-heal + supervisor ticks. */
static _Atomic bool    g_armed            = false;
static _Atomic int     g_rung             = STICKY_RUNG_RETRY;
static _Atomic int64_t g_tip_at_rung      = -1;   /* H* observed when rung entered */
static _Atomic int64_t g_rung_entered_unix = 0;
static _Atomic int64_t g_last_page_unix   = 0;
static _Atomic int64_t g_rearm_until_unix = 0;
static _Atomic uint64_t g_rung_dispatches[STICKY_RUNG_COUNT];
static _Atomic uint64_t g_fires_operator_needed = 0;
static _Atomic uint64_t g_episodes_cleared = 0;
static _Atomic uint64_t g_ladder_cycles    = 0;

/* Livelock backstop state (see STICKY_LIVELOCK_MAX_PASSES). Counts consecutive
 * apply_drive passes that move NEITHER the observed tip NOR the rung index; on
 * reaching the cap the ladder force-advances the current rung so a
 * PROGRESSING-holding rung cannot spin its whole witness window without moving
 * the needle. Reset on every rung entry and episode clear (livelock_reset). */
static _Atomic int      g_livelock_no_progress_passes = 0;
static _Atomic int64_t  g_livelock_last_tip           = -1;
static _Atomic int      g_livelock_last_rung          = -1;
static _Atomic uint64_t g_livelock_force_advances     = 0;

/* Blocker-aware HOLD state (defect D5). While a PERMANENT-class blocker owned by
 * the sync/chain reducer domain this ladder drives is active, the escalator
 * HOLDS: it advances/dispatches NO rung (no reindex/refold can conjure missing
 * shielded history or clear a consensus reject), only re-checks each cadence so
 * the hold releases the instant the blocker clears/retires. Without the hold,
 * a shielded-history-less node holding two permanent utxo_apply blockers
 * (anchor_backfill_gap + nullifier_backfill_gap) would have the ladder churn
 * resnapshot->reindex against a cause no rung can fix. */
static _Atomic bool     g_held_by_permanent    = false; /* current hold state */
static _Atomic uint64_t g_hold_permanent_fires = 0;     /* held drives, monotonic */
static _Atomic int64_t  g_last_hold_warn_unix  = 0;     /* throttle stamp */

/* Pluggable rung actions; NULL = default stub (advance). */
static sticky_rung_fn g_rung_fn[STICKY_RUNG_COUNT];

/* Wall-unix of the last targeted_rederive apply pass that reported repaired
 * work. Within the rung's witness window a follow-up pass that finds nothing
 * NEW actionable holds the rung (the forward stages are still consuming the
 * clamp) instead of advancing on the next 5 s tick into the reindex rung. */
static _Atomic int64_t g_rederive_last_repair_unix = 0;

/* FIX-3: consecutive targeted_rederive repairs that do NOT lift H* past the
 * rung-entry baseline (g_tip_at_rung) — a repair re-clamping the same height.
 * At STICKY_REDERIVE_MAX_FLAT_REPAIRS the rung FAILs so the ladder advances.
 * Reset on every rung (re)entry and on episode clear. */
static _Atomic int g_rederive_flat_repairs = 0;

/* Wall-unix of the last widen_peers discovery kick. Guards against re-kicking
 * every ~30s supervisor tick while the rung holds its window (a dial/DNS/onion
 * pass needs real wall time, and connman_kick_onion_seeds blocks per seed 60s).
 * Reset on episode clear so the next episode kicks immediately. */
static _Atomic int64_t g_widen_last_kick_unix = 0;
#ifdef ZCL_TESTING
/* Refold seams: suppress shutdown/respawn; override the artifact gate. */
static _Atomic bool g_test_suppress_refold_restart = false;
static _Atomic int  g_test_refold_artifact_override = -1;
/* widen_peers seam: counts actual dispatches of the kick functions (as
 * opposed to the early-out "already healthy" / "no connman" paths), so a
 * hermetic test can assert the rung genuinely solicited peers. */
static _Atomic uint64_t g_test_widen_kicks = 0;
#endif

/* Per-rung witness windows (seconds): the slow re-derivation rungs get a long
 * window so a legitimately multi-minute reindex/refold is not prematurely
 * advanced. */
static const int g_rung_window_secs[STICKY_RUNG_COUNT] = {
    [STICKY_RUNG_RETRY]            = 30,
    [STICKY_RUNG_TARGETED_REDERIVE]= 60,
    [STICKY_RUNG_RESNAPSHOT]       = 180,
    [STICKY_RUNG_REINDEX]          = 1200,
    [STICKY_RUNG_SELF_MINT_REFOLD] = 1800,
    [STICKY_RUNG_WIDEN_PEERS]      = 120,
    [STICKY_RUNG_REBOOTSTRAP]      = 3600,
    /* Long: arms + self-respawns, then HOLDS for the restart (fold on next boot). */
    [STICKY_RUNG_REFOLD_FROM_ANCHOR] = 1800,
};

const char *sticky_rung_name(enum sticky_rung r)
{
    switch (r) {
    case STICKY_RUNG_RETRY:             return "retry";
    case STICKY_RUNG_TARGETED_REDERIVE: return "targeted_rederive";
    case STICKY_RUNG_RESNAPSHOT:        return "resnapshot";
    case STICKY_RUNG_REINDEX:           return "reindex";
    case STICKY_RUNG_SELF_MINT_REFOLD:  return "self_mint_refold";
    case STICKY_RUNG_WIDEN_PEERS:       return "widen_peers";
    case STICKY_RUNG_REBOOTSTRAP:       return "rebootstrap";
    case STICKY_RUNG_REFOLD_FROM_ANCHOR: return "refold_from_anchor";
    case STICKY_RUNG_COUNT:             break;
    }
    return "unknown";
}

static int64_t now_unix(void)
{
    return platform_time_wall_unix();
}

/* Provable-tip first (sovereign H*), active-chain tip as fallback. */
static int64_t observe_tip(void)
{
    int32_t hstar = reducer_frontier_provable_tip_cached();
    if (hstar > 0)
        return (int64_t)hstar;
    if (g_ms)
        return (int64_t)active_chain_height(&g_ms->chain_active);
    return -1; // raw-return-ok:no-tip-observable-sentinel-not-an-error
}

/* ── Blocker-aware hold predicate (defect D5) ──────────────────────────────
 *
 * The escalator drives the reducer-frontier / chain-tip SYNC stall (H* not
 * climbing). A PERMANENT-class blocker OWNED BY that same domain is an
 * incomplete-STATE cause — missing shielded history, an unresolvable prevout, a
 * consensus reject — that NO ladder rung can cure: resnapshot/reindex/refold
 * re-derive from bodies the node already has, they cannot conjure history that
 * was never seeded. So while such a blocker is active the ladder must HOLD, not
 * churn expensive/destructive remedies against a wall.
 *
 * This allowlist is deliberately NARROW — only the reducer-pipeline / chain
 * subsystems whose PERMANENT blockers actually pin H*. It must NOT blanket-hold
 * on an unrelated permanent blocker (export/publish/install/wallet/mint tooling,
 * a consensus-bundle gate, etc.): those do not pin the sync tip, and freezing
 * sync recovery on them would itself be a wedge. A blocker matches when its
 * owner_subsystem is in the list OR its id's leading dotted segment is (the
 * reducer stages name blockers "<stage>.<symptom>"; the header_admit stage names
 * its blocker id "header_admit" with an owner of the specific fault). */
static const char *const g_sync_domain_owners[] = {
    "utxo_apply",       /* anchor_backfill_gap, nullifier_backfill_gap,
                         * apply_failed, fatal_store, commit-invariants */
    "script_validate",  /* script_validate.prevout_unresolved */
    "proof_validate",   /* proof_validate.internal_error */
    "header_admit",     /* header_admit (missing_parent linkage) */
    "validate_headers",
    "body_fetch",
    "body_persist",
    "tip_finalize",
    "stage_repair",     /* reducer_frontier.script_undetermined */
    "reducer_frontier",
    "coin_backfill",    /* stage_repair coin backfill permanent tuple */
    "chain",
};

/* True if `s` exactly equals one of the sync-domain owner tokens. */
static bool sync_domain_token(const char *s, size_t len)
{
    if (!s || len == 0)
        return false;
    for (size_t i = 0; i < sizeof(g_sync_domain_owners) /
                           sizeof(g_sync_domain_owners[0]); i++) {
        const char *w = g_sync_domain_owners[i];
        if (strlen(w) == len && strncmp(s, w, len) == 0)
            return true;
    }
    return false;
}

/* True if this blocker belongs to the sync/chain reducer domain the escalator
 * drives — by owner_subsystem, or by the leading dotted segment of its id. */
static bool blocker_in_sync_domain(const struct blocker_snapshot *b)
{
    if (sync_domain_token(b->owner_subsystem, strlen(b->owner_subsystem)))
        return true;
    const char *dot = strchr(b->id, '.');
    size_t seg = dot ? (size_t)(dot - b->id) : strlen(b->id);
    return sync_domain_token(b->id, seg);
}

/* Returns true (and, if `id_out` non-NULL, copies the blocker id) when a
 * PERMANENT-class blocker owned by the sync/chain domain is currently active.
 * Only class == PERMANENT holds escalation; TRANSIENT/DEPENDENCY/RESOURCE
 * blockers are expected during normal stalls and never hold. */
static bool permanent_sync_blocker_active(char id_out[BLOCKER_ID_MAX])
{
    if (id_out)
        id_out[0] = '\0';
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (snaps[i].class != BLOCKER_PERMANENT)
            continue;
        if (!blocker_in_sync_domain(&snaps[i]))
            continue;
        if (id_out)
            snprintf(id_out, BLOCKER_ID_MAX, "%s", snaps[i].id);
        return true;
    }
    return false;
}

/* ── Default rung actions ──────────────────────────────────────────────
 *
 * EVERY rung now has a real in-process surface (no NOT_IMPLEMENTED stubs):
 *   0 retry              — blocker sweep + condition-engine re-attempt.
 *   1 targeted_rederive  — reducer-frontier reconcile apply pass (ungated).
 *   2 resnapshot         — in-process re-derive from the nearest SELF-VERIFIED
 *                          rewind base (newest ratified seal, else compiled
 *                          anchor) via stage_rederive_range when linked; else
 *                          names the reachable base + missing consumer and
 *                          defers to the durable from-bodies rungs. NEVER a
 *                          borrowed-state snapshot pull.
 *   3 reindex            — bounded crash-only reindex-from-blocks (next boot).
 *   4 self_mint_refold   — ARM the durable from-anchor refold of real bodies
 *                          (boot_auto_refold), no respawn — the arm persists
 *                          while the cheaper network rungs get a turn.
 *   5 widen_peers        — connman seed/onion discovery kick.
 *   6 rebootstrap        — collapsed: widen_peers kick UNION ensure-refold-armed
 *                          (a separate from-genesis re-bootstrap is intentionally
 *                          NOT implemented — reindex already re-derives from
 *                          genesis bodies; see rung_rebootstrap_default).
 *   7 refold_from_anchor — TERMINAL: arm (if needed) + trigger the self-respawn
 *                          so the fresh boot re-derives from the verified anchor
 *                          over real bodies. NEVER installs a borrowed value.
 * A lane can still plug a custom action via sticky_escalator_register_rung()
 * with no edit here. A rung whose precondition is absent (no reachable anchor,
 * no verified base) NAMES a typed blocker and returns FAILED so the ladder
 * advances — it never fakes a "done". */

static enum sticky_rung_result rung_retry_default(void)
{
    /* Cheapest: fire any due blocker escape_actions + let the condition engine
     * re-attempt via blocker_supervisor_sweep(). */
    int dispatched = blocker_supervisor_sweep();
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=sticky-retry blocker_escapes=%d unresolved=%d",
                dispatched, condition_engine_get_unresolved_count());
    return STICKY_RUNG_PROGRESSING; /* hold one window to let conditions run */
}

static enum sticky_rung_result rung_targeted_rederive_default(void)
{
    /* Fire any due blocker escape_actions first (cheap, edge-triggered). */
    (void)blocker_supervisor_sweep();

    /* The in-process curative surface for the stale-cursor / rowless-hole
     * class: the reducer-frontier reconcile APPLY pass — the SAME entry the
     * reducer_frontier_reconcile_light Condition's remedy calls
     * (stage_reducer_frontier_reconcile_light). That Condition's detect() is
     * peer-gated on connman_max_peer_height(), which reports peers' static
     * handshake starting_height, so near tip it reads "no peer ahead" and
     * discards the recomputed repair on every tick — a rowless
     * script_validate_log/proof_validate_log hole can pin H* indefinitely
     * while the dry-run recomputes the exact clamp every 5 s with no effect.
     * This rung only runs after the condition layer failed to
     * clear the stall, so it calls the apply entry DIRECTLY — no peer gate,
     * no tear gate. Consensus-safe: the pass only purges non-canonical
     * residue rows and clamps stage cursors; the forward stages re-derive
     * every verdict from PoW-verified on-disk bodies. */
    if (refold_in_progress()) {
        /* A staged refold legitimately re-walks below-anchor heights; the
         * reconcile would drag those cursors back up and fight the fold (the
         * same suspension the Condition's detect() honours). The fold itself
         * is the recovery work — hold this rung for its window. */
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-targeted-rederive skip=refold_in_progress");
        return STICKY_RUNG_PROGRESSING;
    }

    sqlite3 *db = progress_store_db();
    struct main_state *ms = g_ms ? g_ms : sync_monitor_main_state();
    if (!db || !ms) {
        /* NOT LOG_FAIL: that macro returns false == STICKY_RUNG_RESOLVED
         * here, which would report this error path as rung success and
         * disarm the ladder. */
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] targeted_rederive: %s unavailable — "
                 "cannot run the reducer-frontier reconcile",
                 db ? "main_state" : "progress db");
        return STICKY_RUNG_FAILED;
    }

    struct stage_reducer_frontier_reconcile_result rr;
    if (!stage_reducer_frontier_reconcile_light(db, ms, &rr)) {
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] targeted_rederive: reconcile apply "
                 "pass failed (progress store error)");
        return STICKY_RUNG_FAILED;
    }

    if (rr.repaired) {
        atomic_store(&g_rederive_last_repair_unix, now_unix());
        /* Flat-H* churn guard (FIX-3): a repair that does not lift H* past the
         * rung-entry baseline is re-clamping the same height; a climb resets the
         * count, and at the cap the rung FAILs so the ladder advances. */
        int64_t entry = atomic_load(&g_tip_at_rung);
        int flat_repairs = 0;
        if (entry >= 0 && rr.hstar <= (int)entry)
            flat_repairs = atomic_fetch_add(&g_rederive_flat_repairs, 1) + 1;
        else
            atomic_store(&g_rederive_flat_repairs, 0);
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] targeted_rederive repaired: hstar=%d "
                 "entry=%lld flat_repairs=%d coins_applied=%d "
                 "noncanonical_purged=%d script_validate=%d->%d "
                 "proof_validate=%d->%d tip_finalize=%d->%d",
                 rr.hstar, (long long)entry, flat_repairs,
                 rr.coins_applied_height, rr.noncanonical_purged,
                 rr.script_validate_cursor_before,
                 rr.script_validate_cursor_after,
                 rr.proof_validate_cursor_before,
                 rr.proof_validate_cursor_after,
                 rr.tip_finalize_cursor_before,
                 rr.tip_finalize_cursor_after);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-targeted-rederive repaired=1 hstar=%d "
                    "flat_repairs=%d tip_finalize=%d->%d",
                    rr.hstar, flat_repairs, rr.tip_finalize_cursor_before,
                    rr.tip_finalize_cursor_after);
        if (flat_repairs >= STICKY_REDERIVE_MAX_FLAT_REPAIRS)
            return STICKY_RUNG_FAILED; /* re-clamping the same height -> advance */
        return STICKY_RUNG_PROGRESSING; /* clamps durable; stages re-derive */
    }

    /* Nothing NEW actionable, but a pass in the current window DID repair:
     * hold while the stages consume it (see g_rederive_last_repair_unix). */
    int64_t last_repair = atomic_load(&g_rederive_last_repair_unix);
    if (last_repair != 0 &&
        now_unix() - last_repair <
            g_rung_window_secs[STICKY_RUNG_TARGETED_REDERIVE])
        return STICKY_RUNG_PROGRESSING;

    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=sticky-targeted-rederive repaired=0 "
                "refused_coin_tear=%d refused_coin_unknown=%d unresolved=%d",
                (int)rr.refused_coin_tear, (int)rr.refused_coin_unknown,
                condition_engine_get_unresolved_count());
    return STICKY_RUNG_FAILED; /* nothing actionable -> advance the ladder */
}

/* Name a typed DEPENDENCY blocker (retry-forever, never latching) so a stall
 * that reaches a precondition-absent rung is escalatable in blocker diagnostics
 * instead of a silent cycle. Reason text is truncated to fit, never rejected. */
static void name_dependency_blocker(const char *id, const char *reason)
{
    blocker_name_dependency(id, "sticky_escalator", reason);
}

static enum sticky_rung_result rung_resnapshot_default(void)
{
    return sticky_escalator_resnapshot_run(
        g_ms ? g_ms : sync_monitor_main_state(), (int)observe_tip());
}

static bool reindex_replay_executable(int *probe_height_out,
                                      const char **reason_out)
{
    if (probe_height_out)
        *probe_height_out = -1;
    if (reason_out)
        *reason_out = "unknown";

    if (!g_datadir || !g_datadir[0]) {
        if (reason_out)
            *reason_out = "no_datadir";
        return false;
    }

    struct main_state *ms = g_ms ? g_ms : sync_monitor_main_state();
    if (!ms) {
        if (reason_out)
            *reason_out = "no_main_state";
        return false;
    }

    int tip_height = active_chain_height(&ms->chain_active);
    if (tip_height < 0) {
        if (reason_out)
            *reason_out = "no_active_tip";
        return false;
    }

    int probe_height = tip_height < 1 ? 0 : 1;
    if (probe_height_out)
        *probe_height_out = probe_height;

    struct block_index *probe =
        active_chain_at(&ms->chain_active, probe_height);
    if (!block_index_have_data_readable(probe, g_datadir)) {
        if (reason_out)
            *reason_out = "replay_unexecutable";
        return false;
    }
    return true;
}

static enum sticky_rung_result rung_reindex_default(void)
{
    /* Durable, bounded-per-episode crash-only reindex: re-derive the UTXO set
     * from blocks/ on the NEXT boot (full crypto pipeline on replay). The
     * primitive itself caps attempts per anchor episode and marks terminal —
     * but the LADDER does not give up: a terminal reindex simply advances to the
     * deeper rungs. */
    if (!g_datadir) {
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-reindex-skip reason=no_datadir");
        return STICKY_RUNG_NOT_IMPLEMENTED;
    }

    int probe_height = -1;
    const char *reason = "unknown";
    if (!reindex_replay_executable(&probe_height, &reason)) {
        if (boot_auto_reindex_pending(g_datadir))
            boot_auto_reindex_clear(g_datadir);
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] reindex rung skipped: replay-from-blocks "
                 "is not executable (reason=%s probe_h=%d); escalating to "
                 "deeper recovery instead of arming auto_reindex_request",
                 reason, probe_height);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-reindex-skip reason=%s probe_h=%d",
                    reason, probe_height);
        return STICKY_RUNG_FAILED;
    }

    /* The on-disk count is the CROSS-BOOT attempt budget (boot_crashonly
     * treats n in [1..MAX] as "reindex attempt n"), so it must count BOOTS
     * that attempt the rebuild, not runtime dispatches. apply_drive
     * re-dispatches this rung every supervisor tick; without the pending
     * gate, three ticks burn the whole budget to TERMINAL in minutes with no
     * reindex ever running — permanently blocking the ladder's real last rung.
     * A pending request means this lifetime's attempt is already armed (or
     * the one boot consumed is still converging): HOLD and let the
     * restart/boot consume it. */
    if (boot_auto_reindex_is_terminal(g_datadir))
        return STICKY_RUNG_FAILED;   /* budget spent -> go deeper */
    if (boot_auto_reindex_pending(g_datadir)) {
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-reindex-hold reason=request_pending");
        return STICKY_RUNG_PROGRESSING;
    }
    int64_t tip = observe_tip();
    int rc = boot_auto_reindex_request(g_datadir,
                                       (int32_t)(tip > 0 ? tip : 0));
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=sticky-reindex-request anchor=%lld rc=%d",
                (long long)tip, rc);
    if (rc == BOOT_AUTO_REINDEX_TERMINAL)
        return STICKY_RUNG_FAILED;   /* budget spent here -> go deeper */
    if (rc == 0)
        return STICKY_RUNG_FAILED;   /* durable write failed -> go deeper */
    /* Backstop only (the pending gate above makes this unreachable via this
     * rung): a count already past the boot budget is exhausted — persist
     * the terminal state exactly as boot_crashonly would and go deeper.
     * Strictly > MAX so a legitimately armed MAX-th attempt still gets
     * consumed by the next boot instead of being killed here. */
    if (rc > BOOT_AUTO_REINDEX_MAX) {
        (void)boot_auto_reindex_mark_terminal(g_datadir,
                                              (int32_t)(tip > 0 ? tip : 0));
        return STICKY_RUNG_FAILED;
    }
    return STICKY_RUNG_PROGRESSING;  /* armed for next boot; hold a window */
}

/* Shared from-anchor refold arming primitive — the ONE write path (Law 2) for
 * both the self_mint_refold rung (arm only) and the terminal refold_from_anchor
 * rung (arm + trigger the self-respawn). The refold itself always re-derives
 * from the SHA3-checkpoint-bound anchor set + folds anchor->tip over on-disk
 * bodies (boot_refold_from_anchor_reset) — it NEVER installs a borrowed value.
 * `trigger_respawn` false: arm the durable request and let a shallower/cheaper
 * rung still clear the stall (the arm persists on disk, is withdrawn on episode
 * clear, or is consumed when the terminal rung pulls the trigger). true: the
 * durable refold is armed (now or by an earlier rung) — request the supervised
 * self-respawn so the next boot consumes it. Bounded per anchor episode; a
 * genuinely broken/absent artifact NAMES a retry-forever blocker (never a
 * FATAL-loop). `tag` labels the emitted EV_RECOVERY_ACTION. */
static enum sticky_rung_result arm_refold_from_anchor(bool trigger_respawn,
                                                      const char *tag)
{
    if (!g_datadir || !g_datadir[0]) {
        event_emitf(EV_RECOVERY_ACTION, 0, "action=%s reason=no_datadir", tag);
        return STICKY_RUNG_FAILED;
    }
    /* Budget exhausted (prior attempts FATAL-looped to terminal): do NOT re-arm
     * and do NOT respawn into a doomed refold — go deeper / cycle. */
    if (boot_auto_refold_is_terminal(g_datadir)) {
        event_emitf(EV_RECOVERY_ACTION, 0, "action=%s reason=budget_terminal",
                    tag);
        return STICKY_RUNG_FAILED;
    }

    bool already_pending = boot_auto_refold_pending(g_datadir);

    if (!already_pending) {
        /* GATE: a verified anchor snapshot must be reachable (else the boot
         * reset FATAL-refuses) — name the clue, never arm a doomed refold. */
        int32_t anchor_h = -1;
        bool artifact =
            boot_refold_from_anchor_artifact_available(app_runtime_node_db(),
                                                       &anchor_h);
#ifdef ZCL_TESTING
        int ov = atomic_load(&g_test_refold_artifact_override);
        if (ov >= 0) {
            artifact = (ov != 0);
            if (anchor_h < 0)
                anchor_h = (int32_t)reducer_frontier_provable_tip_cached();
        }
#endif
        if (!artifact) {
            char reason[BLOCKER_REASON_MAX];
            snprintf(reason, sizeof(reason),
                     "refold_from_anchor: no verified anchor snapshot reachable "
                     "(anchor_h=%d) — wanted the SHA3-checkpoint-bound "
                     "utxo-anchor.snapshot, produced only by mint/export or a "
                     "fetched bundle. A PERSON decides.", anchor_h);
            name_dependency_blocker(
                "sticky_escalator.refold_no_anchor_artifact", reason);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=%s reason=no_anchor_artifact anchor_h=%d", tag,
                        anchor_h);
            return STICKY_RUNG_FAILED;   /* named the clue -> cycle */
        }

        /* Arm the durable refold (attempts count at CONSUME/boot time). */
        int rc = boot_auto_refold_request(g_datadir, anchor_h);
        if (rc <= 0 || rc == BOOT_AUTO_REFOLD_TERMINAL) {
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=%s-arm-failed anchor=%d rc=%d", tag, anchor_h,
                        rc);
            return STICKY_RUNG_FAILED;
        }
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] %s ARMED anchor=%d respawn=%d — the fresh "
                 "boot re-seeds + re-folds anchor->tip over on-disk bodies", tag,
                 anchor_h, (int)trigger_respawn);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=%s-arm anchor=%d rc=%d respawn=%d", tag, anchor_h, rc,
                    (int)trigger_respawn);
    }

    if (!trigger_respawn)
        /* Armed durably; a shallower/cheaper rung may still clear the stall.
         * The terminal rung triggers the restart that consumes the arm; an
         * episode that self-resolves withdraws it (withdraw_stale_refold_request).
         * Advance so widen_peers/rebootstrap get a turn before the disruptive
         * restart — the arm is the durable progress, so this is a clean advance,
         * not a lost remedy. */
        return STICKY_RUNG_FAILED;

    /* trigger_respawn: the durable refold is armed (now or by an earlier rung) —
     * pull the trigger so the next boot re-derives from the anchor. */
    if (already_pending)
        event_emitf(EV_RECOVERY_ACTION, 0, "action=%s-respawn reason=pending",
                    tag);
#ifdef ZCL_TESTING
    if (!atomic_load(&g_test_suppress_refold_restart))
#endif
    {
        chain_tip_watchdog_request_respawn();
        thread_registry_request_shutdown();
    }
    return STICKY_RUNG_PROGRESSING;   /* armed; the restart consumes it */
}

static enum sticky_rung_result rung_self_mint_refold_default(void)
{
    /* ARM a from-anchor re-fold of the real bodies (the self-derived cure), WITHOUT
     * respawning — the arm is durable and persists while the cheaper network rungs
     * (widen_peers, rebootstrap) get a turn; the terminal refold_from_anchor rung
     * pulls the restart trigger that consumes it. Precondition absent (no verified
     * anchor artifact) -> names a blocker and advances. */
    return arm_refold_from_anchor(/*trigger_respawn=*/false,
                                  "sticky-self-mint-refold");
}

/* Peer-count floor mirrored from conditions/peer_floor_violated.c's
 * PEER_FLOOR_MIN_HEALTHY: same "not enough block-serving outbound peers"
 * symptom. That Condition owns its own detect+cooldown schedule and is
 * P2P-only; THIS rung is reached only after retry/targeted_rederive already
 * failed to clear a stall, so it solicits immediately. */
#define STICKY_WIDEN_PEERS_MIN_HEALTHY 3
#define STICKY_WIDEN_PEERS_KICK_COOLDOWN_SECS 60

static enum sticky_rung_result rung_widen_peers_default(void)
{
    struct connman *cm = sync_monitor_connman();
    if (!cm) {
        /* NOT LOG_FAIL: it returns false == STICKY_RUNG_RESOLVED here. */
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] widen_peers: no connman — cannot solicit");
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-widen-peers-skip reason=no_connman");
        return STICKY_RUNG_FAILED;
    }

    size_t healthy = connman_outbound_healthy_count(cm);
    if (healthy >= STICKY_WIDEN_PEERS_MIN_HEALTHY) {
        /* Peers are not the deficit: fail honestly so the ladder advances to
         * a rung addressing whatever else is stalling the tip. */
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-widen-peers-skip reason=already_healthy "
                    "healthy=%zu min=%d", healthy,
                    STICKY_WIDEN_PEERS_MIN_HEALTHY);
        return STICKY_RUNG_FAILED;
    }

    int64_t now = now_unix();
    int64_t last_kick = atomic_load(&g_widen_last_kick_unix);
    if (last_kick != 0 &&
        now - last_kick < STICKY_WIDEN_PEERS_KICK_COOLDOWN_SECS) {
        /* Kicked this episode + still within cooldown: hold, don't re-thrash
         * seed/onion discovery every supervisor tick. */
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-widen-peers-hold healthy=%zu "
                    "since_kick_secs=%lld", healthy,
                    (long long)(now - last_kick));
        return STICKY_RUNG_PROGRESSING;
    }

    /* Reuse the SAME entry points peer_floor_violated's remedy calls: re-add
     * fixed seeds + retry DNS resolve, and — with zero healthy outbound — the
     * onion-directory peer-of-last-resort fetch (harvests clearnet IPs from
     * /directory.json on known .onion seeds; the eclipsed/partitioned path). */
    bool zero_outbound = healthy == 0;
    connman_kick_seed_discovery(cm);
    if (zero_outbound)
        connman_kick_onion_seeds(cm);
    atomic_store(&g_widen_last_kick_unix, now);
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_widen_kicks, 1u);
#endif

    LOG_WARN("sticky_escalator",
             "[sticky_escalator] widen_peers: healthy=%zu below floor=%d — "
             "kicked seed discovery%s",
             healthy, STICKY_WIDEN_PEERS_MIN_HEALTHY,
             zero_outbound ? "+onion-directory (zero outbound)" : "");
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=sticky-widen-peer-discovery healthy=%zu min=%d "
                "onion_kick=%d", healthy, STICKY_WIDEN_PEERS_MIN_HEALTHY,
                (int)zero_outbound);
    return STICKY_RUNG_PROGRESSING;
}

static enum sticky_rung_result rung_rebootstrap_default(void)
{
    /* COLLAPSED rung (fail-safe-architecture.md §1: the ladder target is
     * rederive -> restart-with-refold-armed -> page). A separate from-genesis
     * re-bootstrap is intentionally NOT implemented here: from-genesis
     * re-derivation is already the reindex rung (crash-only replay from blocks/),
     * and a "fresh peer/header re-bootstrap" is exactly the widen_peers kick
     * (re-add fixed seeds, retry DNS, and — with zero outbound — the onion
     * directory peer-of-last-resort that harvests clearnet IPs). This last-resort
     * rung UNIONS the two remedies that actually move a wedged-but-alive node:
     * re-solicit peers AND ensure the durable from-anchor refold stays armed so
     * the terminal rung can consume it. */
    (void)rung_widen_peers_default();   /* re-solicit peers (its own cooldown) */
    /* Keep the from-anchor refold armed (no respawn — the terminal rung 7 pulls
     * the trigger). Precondition absent -> names a blocker, does not fake work. */
    (void)arm_refold_from_anchor(/*trigger_respawn=*/false,
                                 "sticky-rebootstrap-refold");
    /* ADVANCE to the terminal refold rung: widen_peers (rung 5) already held a
     * witness window for a fresh peer set to land; this last-resort rung does a
     * final re-kick + keeps the refold armed, then hands off so the terminal
     * rung can fire the decisive self-respawn rather than parking on the peer
     * cooldown for this rung's (long) window. */
    return STICKY_RUNG_FAILED;
}

/* DEEPEST rung — runtime refold from the newest verified anchor
 * (fail-safe-architecture.md §1 rung 3 / §4 item 5). Design = ARM + supervised
 * self-respawn: the fresh boot runs the SAME boot_refold_from_anchor_reset
 * (Law 2). Honest PROGRESSING ("armed"), never a fake "done"; bounded; GATED on
 * an anchor artifact (absent -> name the missing clue). */
static enum sticky_rung_result rung_refold_from_anchor_default(void)
{
    /* TERMINAL: arm the durable from-anchor refold if not already armed (by this
     * rung or an earlier self_mint_refold/rebootstrap rung) and TRIGGER the
     * supervised self-respawn so the fresh boot consumes it — re-deriving from
     * the SHA3-checkpoint-bound anchor set + folding anchor->tip over on-disk
     * bodies. NEVER installs a borrowed value; a missing/exhausted artifact
     * names a retry-forever blocker and returns FAILED so the ladder cycles
     * (never-give-up) and emits the non-latching operator page. */
    return arm_refold_from_anchor(/*trigger_respawn=*/true, "sticky-refold");
}

static const sticky_rung_fn g_rung_default[STICKY_RUNG_COUNT] = {
    [STICKY_RUNG_RETRY]            = rung_retry_default,
    [STICKY_RUNG_TARGETED_REDERIVE]= rung_targeted_rederive_default,
    [STICKY_RUNG_RESNAPSHOT]       = rung_resnapshot_default,
    [STICKY_RUNG_REINDEX]          = rung_reindex_default,
    [STICKY_RUNG_SELF_MINT_REFOLD] = rung_self_mint_refold_default,
    [STICKY_RUNG_WIDEN_PEERS]      = rung_widen_peers_default,
    [STICKY_RUNG_REBOOTSTRAP]      = rung_rebootstrap_default,
    [STICKY_RUNG_REFOLD_FROM_ANCHOR] = rung_refold_from_anchor_default,
};

static sticky_rung_fn rung_action(enum sticky_rung r)
{
    sticky_rung_fn f = g_rung_fn[r];
    return f ? f : g_rung_default[r];
}

/* ── Ladder transitions ────────────────────────────────────────────── */

/* Reset the livelock backstop tracker: a fresh rung (or a cleared episode) is
 * genuine forward motion, so the zero-progress pass count starts over. */
static void livelock_reset(void)
{
    atomic_store(&g_livelock_no_progress_passes, 0);
    atomic_store(&g_livelock_last_tip, (int64_t)-1);
    atomic_store(&g_livelock_last_rung, -1);
}

static void enter_rung(enum sticky_rung r, int64_t now)
{
    atomic_store(&g_rung, (int)r);
    atomic_store(&g_tip_at_rung, observe_tip());
    atomic_store(&g_rung_entered_unix, now);
    atomic_store(&g_rederive_flat_repairs, 0);
    sticky_resnapshot_gate_reset();
    livelock_reset();
}

/* Withdraw a pending (non-terminal) on-disk auto_reindex_request once THIS
 * episode has genuinely resolved (tip proven strictly past the request's
 * anchor). The reindex rung arms boot_auto_reindex_request() durably for the
 * NEXT boot; if the stall self-resolves first, the marker outlives its episode
 * and would force a needless chainstate rebuild on restart.
 * boot_auto_reindex_pending() excludes the TERMINAL marker, so this never
 * touches the budget-exhausted/operator-paged state — only a live, still-armed
 * request the tip has since proven past. */
static void withdraw_stale_reindex_request(int64_t tip)
{
    if (!g_datadir || !g_datadir[0])
        return;
    if (!boot_auto_reindex_pending(g_datadir))
        return;
    int32_t anchor = 0;
    int count = 0;
    if (!boot_auto_reindex_status(g_datadir, &anchor, &count))
        return;
    if (tip <= (int64_t)anchor)
        return;
    boot_auto_reindex_clear(g_datadir);
    LOG_INFO("sticky_escalator",
             "[sticky_escalator] withdrew stale auto_reindex_request "
             "anchor=%d count=%d: tip=%lld progressed past it, the reindex "
             "would have been needless",
             anchor, count, (long long)tip);
}

/* Withdraw a pending (non-terminal) on-disk auto_refold_request once THIS
 * episode has genuinely resolved (tip proven past the refold anchor). The
 * self_mint_refold / rebootstrap rungs arm boot_auto_refold_request() durably so
 * the terminal rung's self-respawn can consume it; if the stall self-resolves
 * before that respawn happens (a shallower remedy or the network cleared it),
 * the marker outlives its episode and would force a needless from-anchor refold
 * on the next boot — a violation of the auto-terminating-remedy invariant, the
 * exact defect withdraw_stale_reindex_request cures for the reindex marker.
 * boot_auto_refold_pending() already excludes the TERMINAL marker (budget
 * exhausted / operator paged), so this never touches that state — only a live,
 * still-armed request for an anchor the tip has since proven past. */
static void withdraw_stale_refold_request(int64_t tip)
{
    if (!g_datadir || !g_datadir[0])
        return;
    if (!boot_auto_refold_pending(g_datadir))
        return;
    int32_t anchor = 0;
    int count = 0;
    if (!boot_auto_refold_status(g_datadir, &anchor, &count))
        return;
    if (tip <= (int64_t)anchor)
        return;
    boot_auto_refold_clear(g_datadir);
    LOG_INFO("sticky_escalator",
             "[sticky_escalator] withdrew stale auto_refold_request "
             "anchor=%d count=%d: tip=%lld progressed past it, the refold "
             "would have been needless",
             anchor, count, (long long)tip);
}

static void clear_episode(int64_t now, int64_t tip)
{
    (void)now;
    atomic_store(&g_armed, false);
    atomic_store(&g_rung, STICKY_RUNG_RETRY);
    atomic_store(&g_tip_at_rung, -1);
    atomic_store(&g_rearm_until_unix, 0);
    atomic_store(&g_rederive_last_repair_unix, 0);
    atomic_store(&g_rederive_flat_repairs, 0);
    sticky_resnapshot_gate_reset();
    atomic_store(&g_widen_last_kick_unix, 0);
    /* Release the blocker-aware hold state (defect D5): the tip climbed, so the
     * episode genuinely cleared. The fires counter stays monotonic (diagnostic);
     * reset the current-state bool + warn throttle so a fresh episode warns at
     * once. */
    atomic_store(&g_held_by_permanent, false);
    atomic_store(&g_last_hold_warn_unix, 0);
    atomic_fetch_add(&g_episodes_cleared, 1u);
    livelock_reset();
    withdraw_stale_reindex_request(tip);
    withdraw_stale_refold_request(tip);
    /* Release any operator_needed latch this episode raised: the tip
     * progressed, so the symptom genuinely cleared. This is the matching clear
     * for note_cycling_page()'s (terminal=0) page so recovery is automatic. */
    event_emitf(EV_CONDITION_CLEARED, 0,
                "condition=sticky_ladder_cycling reason=tip_progressed");
    LOG_INFO("sticky_escalator",
             "[sticky_escalator] episode cleared: tip progressed, ladder reset");
}

/* Non-latching page: a periodic "ladder is cycling, attention welcome" notice.
 * Rate-limited; NEVER a give-up. Per plan R4: keep the page, drop the latch. */
static void note_cycling_page(int64_t now, enum sticky_rung deepest)
{
    int64_t last = atomic_load(&g_last_page_unix);
    if (last != 0 && now - last < STICKY_PAGE_MIN_INTERVAL_SECS)
        return;
    atomic_store(&g_last_page_unix, now);
    atomic_fetch_add(&g_fires_operator_needed, 1u);
    LOG_WARN("sticky_escalator",
             "[sticky_escalator] ladder cycled through the deepest rung (%s) "
             "without clearing; RE-ARMING and continuing (NOT giving up) — "
             "operator attention welcome but not required",
             sticky_rung_name(deepest));
    /* Non-latching: emitted as a recurring notice, NOT a terminal state. The
     * health surface may show "recovering, attention welcome"; the ladder keeps
     * driving on its own. */
    event_emitf(EV_OPERATOR_NEEDED, 0,
                "condition=sticky_ladder_cycling rung=%s cycles=%llu "
                "terminal=0 recoverable=1",
                sticky_rung_name(deepest),
                (unsigned long long)atomic_load(&g_ladder_cycles));
}

/* The core step, shared by drive() and the test seam. `now` is wall-unix;
 * `tip` is the observed provable tip (injected in tests). */
static void apply_drive(int64_t tip, int64_t now)
{
    /* A queued callback must not arm cross-boot work during store teardown. */
    if (thread_registry_shutdown_requested()) return;
    if (!atomic_load(&g_armed)) {
        /* Generic CRITICAL conditions are only a belt-and-suspenders trigger
         * while chain work is pending. Named stall signals use note_stall(). */
        if (!sticky_trigger_auto_arm_allowed(
                g_ms, tip,
                condition_engine_get_unresolved_critical_count()))
            return;
        atomic_store(&g_armed, true);
        enter_rung(STICKY_RUNG_RETRY, now);
    }

    /* Honour the post-deepest-rung cooldown before re-driving. */
    int64_t rearm = atomic_load(&g_rearm_until_unix);
    if (rearm != 0) {
        if (now < rearm)
            return;
        atomic_store(&g_rearm_until_unix, 0);
        enter_rung(STICKY_RUNG_RETRY, now);
    }

    /* Progress check: any climb past the entry tip clears the whole episode. */
    int64_t entry = atomic_load(&g_tip_at_rung);
    if (entry >= 0 && tip >= entry + STICKY_PROGRESS_MARGIN) {
        clear_episode(now, tip);
        return;
    }

    /* Blocker-aware HOLD (defect D5): a PERMANENT-class blocker owned by the
     * sync/chain reducer domain this ladder drives is an incomplete-STATE cause
     * that NO rung can cure. Churning resnapshot/reindex/refold against it wastes
     * hours and can destroy useful state — e.g. logging
     * "rung 'resnapshot' made no progress — advancing to 'reindex'" while two
     * permanent utxo_apply gap blockers are active and no rung can clear them.
     * HOLD: advance/dispatch NO
     * rung; re-check on the normal cadence so the hold releases the instant the
     * blocker clears/retires. Only PERMANENT holds — TRANSIENT/DEPENDENCY/
     * RESOURCE blockers are expected during normal stalls and their remedies are
     * exactly what the shallower rungs run. */
    {
        char held_id[BLOCKER_ID_MAX];
        if (permanent_sync_blocker_active(held_id)) {
            atomic_store(&g_held_by_permanent, true);
            atomic_fetch_add(&g_hold_permanent_fires, 1u);
            enum sticky_rung held_rung = (enum sticky_rung)atomic_load(&g_rung);
            int64_t last = atomic_load(&g_last_hold_warn_unix);
            if (last == 0 || now - last >= STICKY_HOLD_WARN_MIN_INTERVAL_SECS) {
                atomic_store(&g_last_hold_warn_unix, now);
                LOG_WARN("sticky_escalator",
                         "[sticky_escalator] escalation held: permanent blocker "
                         "'%s' owns this stall — rungs cannot cure incomplete "
                         "state (holding at rung '%s', re-checking each cadence)",
                         held_id, sticky_rung_name(held_rung));
                event_emitf(EV_RECOVERY_ACTION, 0,
                            "action=sticky-escalation-held blocker=%s rung=%s "
                            "terminal=0 recoverable=1",
                            held_id, sticky_rung_name(held_rung));
            }
            /* A hold is not a zero-progress rung spin; keep the livelock tracker
             * from counting held passes so it never force-advances past a wall. */
            livelock_reset();
            return;
        }
        atomic_store(&g_held_by_permanent, false);
    }

    enum sticky_rung cur = (enum sticky_rung)atomic_load(&g_rung);
    int64_t entered = atomic_load(&g_rung_entered_unix);
    int window = g_rung_window_secs[cur];

    /* Livelock backstop: a pass that moves NEITHER the observed tip NOR the
     * rung index is zero-progress. After STICKY_LIVELOCK_MAX_PASSES consecutive
     * zero-progress passes the ladder FORCE-advances the current rung — never
     * repeating the stuck action — regardless of the rung's own (possibly long)
     * witness window. This bounds a rung that returns PROGRESSING every pass
     * while nothing actually moves (the ladder-livelock class). The tracker is
     * reset on every rung entry / episode clear (livelock_reset), so a genuine
     * rung advance or tip climb never trips it. */
    {
        int64_t prev_tip = atomic_load(&g_livelock_last_tip);
        int     prev_rung = atomic_load(&g_livelock_last_rung);
        bool no_progress = (prev_rung == (int)cur) && (prev_tip >= 0) &&
                           (tip <= prev_tip);
        if (no_progress) {
            int np = atomic_fetch_add(&g_livelock_no_progress_passes, 1) + 1;
            if (np >= STICKY_LIVELOCK_MAX_PASSES) {
                atomic_fetch_add(&g_livelock_force_advances, 1u);
                LOG_WARN("sticky_escalator",
                         "[sticky_escalator] livelock backstop: rung '%s' spun "
                         "%d passes with zero tip/rung progress (tip=%lld) — "
                         "force-advancing the ladder (never repeat)",
                         sticky_rung_name(cur), np, (long long)tip);
                event_emitf(EV_RECOVERY_ACTION, 0,
                            "action=sticky-livelock-force-advance rung=%s "
                            "passes=%d tip=%lld",
                            sticky_rung_name(cur), np, (long long)tip);
                if (cur + 1 < STICKY_RUNG_COUNT) {
                    enter_rung((enum sticky_rung)(cur + 1), now); /* resets tracker */
                } else {
                    /* Deepest rung: cycle with a cooldown + non-latching page,
                     * the same terminal handling as a window-lapse exhaust. */
                    atomic_fetch_add(&g_ladder_cycles, 1u);
                    note_cycling_page(now, cur);
                    atomic_store(&g_rearm_until_unix,
                                 now + STICKY_REARM_COOLDOWN_SECS);
                    livelock_reset();
                }
                return;
            }
        } else {
            atomic_store(&g_livelock_no_progress_passes, 0);
        }
        atomic_store(&g_livelock_last_tip, tip);
        atomic_store(&g_livelock_last_rung, (int)cur);
    }

    /* Most rung actions are idempotent nudges and may run each tick.  The
     * resnapshot action is different: it rewinds a range. Dispatch it exactly
     * once per rung entry, then let the forward stages consume that rewind.
     * Reaching the pre-rewind entry frontier is the exact completion witness;
     * requiring the generic +2 margin here would advance into deeper recovery
     * after a successful catch-up merely because no new block arrived. */
    enum sticky_rung_result res;
    if (cur == STICKY_RUNG_RESNAPSHOT) {
        enum sticky_resnapshot_gate_decision decision =
            sticky_resnapshot_gate_decide(entry, tip);
        if (decision == STICKY_RESNAPSHOT_COMPLETE) {
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=sticky-resnapshot-complete tip=%lld "
                        "entry=%lld dispatches=1",
                        (long long)tip, (long long)entry);
            clear_episode(now, tip);
            return;
        }
        if (decision == STICKY_RESNAPSHOT_HOLD) {
            res = STICKY_RUNG_PROGRESSING;
        } else {
            res = rung_action(cur)();
            atomic_fetch_add(&g_rung_dispatches[cur], 1u);
            sticky_resnapshot_gate_finish(res == STICKY_RUNG_PROGRESSING);
        }
    } else {
        res = rung_action(cur)();
        atomic_fetch_add(&g_rung_dispatches[cur], 1u);
    }

    if (res == STICKY_RUNG_RESOLVED) {
        clear_episode(now, tip);
        return;
    }
    if (res == STICKY_RUNG_PROGRESSING) {
        /* Hold this rung until its witness window lapses without tip progress. */
        if (now - entered < window)
            return;
        /* Window lapsed with no progress — fall through to advance. */
    }

    /* Advance (FAILED / NOT_IMPLEMENTED, or PROGRESSING-window-lapsed). */
    if (cur + 1 < STICKY_RUNG_COUNT) {
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] rung '%s' made no progress (res=%d) — "
                 "advancing to '%s'",
                 sticky_rung_name(cur), (int)res,
                 sticky_rung_name((enum sticky_rung)(cur + 1)));
        enter_rung((enum sticky_rung)(cur + 1), now);
        return;
    }

    /* Deepest rung exhausted WITHOUT clearing. DO NOT give up: re-arm to rung 0
     * after a cooldown and keep cycling. Emit a non-latching cycling page. */
    atomic_fetch_add(&g_ladder_cycles, 1u);
    note_cycling_page(now, cur);
    atomic_store(&g_rearm_until_unix, now + STICKY_REARM_COOLDOWN_SECS);
}

/* ── Public API ────────────────────────────────────────────────────── */
void sticky_escalator_set_datadir(const char *datadir)
{
    g_datadir = datadir; /* process-lifetime string from boot ctx */
}

void sticky_escalator_register_rung(enum sticky_rung rung, sticky_rung_fn fn)
{
    if ((int)rung < 0 || rung >= STICKY_RUNG_COUNT)
        return;
    g_rung_fn[rung] = fn;
}

void sticky_escalator_note_stall(const char *cause)
{
    if (thread_registry_shutdown_requested()) return;
    int64_t now = now_unix();
    bool was = atomic_exchange(&g_armed, true);
    if (!was) {
        enter_rung(STICKY_RUNG_RETRY, now);
        atomic_store(&g_rearm_until_unix, 0);
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] ARMED by stall cause=%s — entering "
                 "always-terminating remedy ladder at rung 'retry'",
                 cause ? cause : "(unknown)");
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-ladder-armed cause=%s",
                    cause ? cause : "unknown");
    }
}

void sticky_escalator_drive(void)
{
    if (!g_ms) return;
    apply_drive(observe_tip(), now_unix());
}

static void sticky_escalator_tick(struct liveness_contract *c)
{
    (void)c;
    sticky_escalator_drive();
    supervisor_progress(atomic_load(&g_id),
                        (int64_t)atomic_load(&g_rung));
}

void sticky_escalator_register(struct main_state *ms)
{
    if (!ms) return;
    if (atomic_load(&g_id) != SUPERVISOR_INVALID_ID) return; /* idempotent */
    g_ms = ms;
    liveness_contract_init(&g_contract, "op.sticky_escalator");
    atomic_store(&g_contract.period_secs, (int64_t)30);
    atomic_store(&g_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_contract.progress_max_quiet_us, (int64_t)0);
    g_contract.on_tick  = sticky_escalator_tick;
    g_contract.on_stall = NULL;
    supervisor_domains_init();
    atomic_store(&g_id, supervisor_register_in_domain(g_op_sup, &g_contract));
    if (atomic_load(&g_id) == SUPERVISOR_INVALID_ID)
        LOG_WARN("sticky_escalator", "[sticky_escalator] WARN register failed");
}

bool sticky_escalator_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    int64_t now = now_unix();
    enum sticky_rung cur = (enum sticky_rung)atomic_load(&g_rung);
    json_push_kv_bool(out, "registered",
                      atomic_load(&g_id) != SUPERVISOR_INVALID_ID);
    json_push_kv_bool(out, "armed", atomic_load(&g_armed));
    json_push_kv_str(out, "current_rung", sticky_rung_name(cur));
    json_push_kv_int(out, "current_rung_index", (int64_t)cur);
    json_push_kv_int(out, "rung_count", (int64_t)STICKY_RUNG_COUNT);
    json_push_kv_int(out, "tip_at_rung", atomic_load(&g_tip_at_rung));
    json_push_kv_int(out, "observed_tip", observe_tip());
    int64_t entered = atomic_load(&g_rung_entered_unix);
    json_push_kv_int(out, "rung_age_secs",
                     entered ? (now - entered) : 0);
    json_push_kv_int(out, "rung_window_secs", (int64_t)g_rung_window_secs[cur]);
    int64_t rearm = atomic_load(&g_rearm_until_unix);
    json_push_kv_int(out, "rearm_in_secs",
                     (rearm && rearm > now) ? (rearm - now) : 0);
    json_push_kv_int(out, "ladder_cycles",
                     (int64_t)atomic_load(&g_ladder_cycles));
    json_push_kv_int(out, "episodes_cleared",
                     (int64_t)atomic_load(&g_episodes_cleared));
    json_push_kv_int(out, "fires_operator_needed_nonlatching",
                     (int64_t)atomic_load(&g_fires_operator_needed));
    json_push_kv_int(out, "livelock_no_progress_passes",
                     (int64_t)atomic_load(&g_livelock_no_progress_passes));
    json_push_kv_int(out, "livelock_max_passes",
                     (int64_t)STICKY_LIVELOCK_MAX_PASSES);
    json_push_kv_int(out, "livelock_force_advances",
                     (int64_t)atomic_load(&g_livelock_force_advances));
    json_push_kv_int(out, "resnapshot_dispatch_state",
                     sticky_resnapshot_gate_state());
    json_push_kv_bool(out, "auto_arm_suppressed_at_tip", sticky_trigger_auto_arm_suppressed());
    json_push_kv_int(out, "auto_arm_suppressions",
                     (int64_t)sticky_trigger_auto_arm_suppressions());
    json_push_kv_int(out, "unresolved_conditions",
                     condition_engine_get_unresolved_count());

    /* Blocker-aware hold (defect D5): current hold state, held-drive count, and
     * the id of the permanent sync-domain blocker owning the stall (recomputed
     * live from the registry so it reflects a clear/retire immediately). */
    char held_id[BLOCKER_ID_MAX];
    bool held_now = permanent_sync_blocker_active(held_id);
    json_push_kv_bool(out, "held_by_permanent_blocker", held_now);
    json_push_kv_str(out, "permanent_hold_blocker_id",
                     held_now ? held_id : "");
    json_push_kv_int(out, "permanent_hold_fires",
                     (int64_t)atomic_load(&g_hold_permanent_fires));

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < STICKY_RUNG_COUNT; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        json_push_kv_str(&o, "rung", sticky_rung_name((enum sticky_rung)i));
        json_push_kv_int(&o, "dispatches",
                         (int64_t)atomic_load(&g_rung_dispatches[i]));
        json_push_kv_bool(&o, "pluggable_action_set", g_rung_fn[i] != NULL);
        json_push_back(&arr, &o);
        json_free(&o);
    }
    json_push_kv(out, "rungs", &arr);
    json_free(&arr);
    return true;
}

#ifdef ZCL_TESTING
void sticky_escalator_test_reset(void)
{
    atomic_store(&g_armed, false);
    atomic_store(&g_rung, STICKY_RUNG_RETRY);
    atomic_store(&g_tip_at_rung, -1);
    atomic_store(&g_rung_entered_unix, 0);
    atomic_store(&g_last_page_unix, 0);
    atomic_store(&g_rearm_until_unix, 0);
    atomic_store(&g_fires_operator_needed, 0u);
    atomic_store(&g_episodes_cleared, 0u);
    atomic_store(&g_ladder_cycles, 0u);
    atomic_store(&g_rederive_last_repair_unix, (int64_t)0);
    atomic_store(&g_rederive_flat_repairs, 0);
    sticky_resnapshot_gate_reset();
    sticky_trigger_test_reset();
    atomic_store(&g_widen_last_kick_unix, (int64_t)0);
    atomic_store(&g_livelock_no_progress_passes, 0);
    atomic_store(&g_livelock_last_tip, (int64_t)-1);
    atomic_store(&g_livelock_last_rung, -1);
    atomic_store(&g_livelock_force_advances, 0u);
    atomic_store(&g_held_by_permanent, false);
    atomic_store(&g_hold_permanent_fires, 0u);
    atomic_store(&g_last_hold_warn_unix, (int64_t)0);
    atomic_store(&g_test_suppress_refold_restart, false);
    atomic_store(&g_test_refold_artifact_override, -1);
    atomic_store(&g_test_widen_kicks, 0u);
    for (int i = 0; i < STICKY_RUNG_COUNT; i++) {
        atomic_store(&g_rung_dispatches[i], 0u);
        g_rung_fn[i] = NULL;
    }
}

enum sticky_rung sticky_escalator_test_drive(int64_t injected_tip,
                                             int64_t now_unix_in)
{
    apply_drive(injected_tip, now_unix_in);
    return (enum sticky_rung)atomic_load(&g_rung);
}

bool sticky_escalator_test_armed(void)
{
    return atomic_load(&g_armed);
}

void sticky_escalator_test_set_suppress_refold_restart(bool s)
{ atomic_store(&g_test_suppress_refold_restart, s); }

void sticky_escalator_test_set_refold_artifact_available(int v)
{ atomic_store(&g_test_refold_artifact_override, v); }

uint64_t sticky_escalator_test_widen_kicks(void)
{ return atomic_load(&g_test_widen_kicks); }

uint64_t sticky_escalator_test_livelock_force_advances(void)
{ return atomic_load(&g_livelock_force_advances); }

uint64_t sticky_escalator_test_rung_dispatches(enum sticky_rung rung)
{
    if ((int)rung < 0 || rung >= STICKY_RUNG_COUNT)
        return 0;
    return atomic_load(&g_rung_dispatches[rung]);
}

void sticky_escalator_test_set_pending_work(int v)
{ sticky_trigger_test_set_pending_work(v); }

bool sticky_escalator_test_held_by_permanent(void)
{ return atomic_load(&g_held_by_permanent); }

uint64_t sticky_escalator_test_permanent_hold_fires(void)
{ return atomic_load(&g_hold_permanent_fires); }
#endif
