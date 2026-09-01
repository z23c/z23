/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_selfheal_ladder — implementation of the sovereign 3-rung self-heal
 * ladder for the NAMED-REMEDY shielded-history gap.  See the header + the Move
 * 2a contract block in conditions/sapling_anchor_frontier_unavailable.h.
 *
 * CONSENSUS PARITY: every rung re-derives (Rung A: nullifier_backfill_service —
 * populate-only over local bodies; the from-anchor/genesis refold — recomputes
 * the SAME cumulative Sapling anchor tree) or CHECKPOINT-verifies (Rung B: the
 * atomic keystone installer, ROM/PoW-authority gated) or NAMES the exact need
 * (Rung C).  A cursor flips to complete/0 only after a complete verified set
 * commits atomically (the walker / installer own that); nothing here forges,
 * borrows-unverified, or relaxes a check.  This TU intentionally does NOT
 * include shielded_history_import_service.h — the BORROWED import stays reachable
 * only through its own owner-gated verb.
 *
 * TENACITY I3 (no-new-repair-rung): this rung heals a LEGITIMATELY-incomplete
 * shielded history — the intended result of a frontier-only fast-sync seed —
 * NOT wrong state emitted by a buggy writer.  The shielded WRITERS already fail
 * CLOSED (fold_sapling writes nothing on a root mismatch; the atomic installer
 * rolls back on any anomaly), which is exactly why the wedge is a SAFE named
 * blocker to re-derive from rather than silent corruption.  The rung re-derives
 * proven state; it never fakes the missing history.  Write-time-invariant
 * proof: test_sapling_anchor_frontier_condition (case (c) — a mismatched-root
 * seed writes NOTHING and the fold stays failed-closed). */
// repair-rung-ok:test_sapling_anchor_frontier_condition

#include "conditions/shielded_selfheal_ladder.h"

#include "conditions/sapling_anchor_frontier_unavailable.h" /* shielded_selfheal_* + enum */
#include "conditions/checkpoint_header_solution_repair.h" /* solution-available gate */
#include "chain/checkpoints.h"                             /* get_sha3_utxo_checkpoint */
#include "core/uint256.h"
#include "config/boot.h"
#include "config/consensus_state_install_runtime.h"
#include "config/runtime.h"
#include "controllers/agent_controller.h"
#include "controllers/shielded_gap_remedy_controller.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_anchors.h" /* SAPLING_ANCHOR_FRONTIER_CONDITION_NAME */
#include "json/json.h"
#include "models/block.h"
#include "services/nullifier_backfill_service.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SSL_SUBSYS "condition"
#define SSL_COND_NAME SAPLING_ANCHOR_FRONTIER_CONDITION_NAME

/* Ladder per-episode state.
 *
 * g_selfheal_progress_base: the durable heal cursor at the last .progressing
 * snapshot (max of the nullifier backfill resume height and H*). -1 =
 * unsnapshotted; re-armed at each named-remedy rising edge.  The hook returns
 * true (resetting the attempt budget WITHOUT clearing) only when the cursor
 * advances past this baseline, then re-snapshots — so pure churn (frozen
 * cursor) still exhausts the budget in bounded time and pages.
 *
 * g_selfheal_named_height: the exact first-missing body/artifact height Rung C
 * most recently named (surfaced in the condition's detail JSON); -1 = none. */
static _Atomic int64_t g_selfheal_progress_base = -1;
static _Atomic int64_t g_selfheal_named_height = -1;

/* Pure rung selection from explicit observations — no IO, unit-testable. */
enum shielded_selfheal_rung shielded_selfheal_select_rung(
    enum shielded_gap_kind gap, bool nullifier_bodies_ok,
    bool anchor_refold_reachable, bool bundle_present)
{
    switch (gap) {
    case SHIELDED_GAP_NULLIFIER_ONLY:
        if (nullifier_bodies_ok)
            return SHIELDED_SELFHEAL_RUNG_A_NULLIFIER;
        break;
    case SHIELDED_GAP_ANCHOR_ONLY:
    case SHIELDED_GAP_BOTH:
        if (anchor_refold_reachable)
            return SHIELDED_SELFHEAL_RUNG_A_ANCHOR;
        break;
    case SHIELDED_GAP_NONE:
    default:
        return SHIELDED_SELFHEAL_RUNG_NONE;
    }
    if (bundle_present)
        return SHIELDED_SELFHEAL_RUNG_B_INSTALL;
    return SHIELDED_SELFHEAL_RUNG_C_NAMED_NEED;
}

/* SEPARATE authorization for the SOVEREIGN auto path (Rungs A/B).  Reads the
 * borrowed-import containment purely for its datadir CLASSIFICATION — never its
 * auto_execute field (which stays the untouched owner-gate for the borrowed
 * -import-complete-shielded verb).  Defers to the operator only on a throwaway
 * -COPY- copy-prove datadir, where the borrowed import is run by hand. */
bool shielded_selfheal_sovereign_authorized(void)
{
    struct shielded_gap_containment c;
    shielded_gap_remedy_eval_containment(&c);
    if (c.datadir_is_copy_marked)
        return false;
    return true;
}

/* Compose the exact first-missing named need from the two evidence sources. */
int64_t shielded_selfheal_named_need(int64_t nullifier_missing,
                                     int64_t body_missing)
{
    if (nullifier_missing < 0)
        return body_missing;
    if (body_missing < 0)
        return nullifier_missing;
    return nullifier_missing < body_missing ? nullifier_missing : body_missing;
}

int64_t shielded_selfheal_last_named_height(void)
{
    return atomic_load(&g_selfheal_named_height);
}

void shielded_selfheal_reset_episode(void)
{
    atomic_store(&g_selfheal_progress_base, -1);
    atomic_store(&g_selfheal_named_height, -1);
}

/* Durable heal cursor for the .progressing hook: the max of the nullifier
 * backfill resume height (decimal-string blob under NULLIFIER_BACKFILL_RESUME_
 * KEY) and H* (which climbs as an anchor refold / bundle install lands).  -1
 * when neither is known. */
static int64_t selfheal_progress_cursor(sqlite3 *db)
{
    int64_t cur = -1;
    if (db) {
        char buf[32];
        size_t len = 0;
        bool found = false;
        if (progress_meta_get(db, NULLIFIER_BACKFILL_RESUME_KEY, buf,
                              sizeof(buf) - 1, &len, &found) &&
            found && len < sizeof(buf)) {
            buf[len] = '\0';
            long long v = strtoll(buf, NULL, 10);
            if ((int64_t)v > cur)
                cur = (int64_t)v;
        }
    }
    int32_t hstar = reducer_frontier_provable_tip_cached();
    if ((int64_t)hstar > cur)
        cur = (int64_t)hstar;
    return cur;
}

bool shielded_selfheal_progressing(bool named_episode)
{
    if (!named_episode)
        return false;
    int64_t cur = selfheal_progress_cursor(progress_store_db());
    if (cur < 0)
        return false;                 /* nothing to measure yet */
    int64_t base = atomic_load(&g_selfheal_progress_base);
    if (base < 0) {
        atomic_store(&g_selfheal_progress_base, cur);
        return false;                 /* first observation: snapshot only */
    }
    if (cur > base) {
        atomic_store(&g_selfheal_progress_base, cur);   /* re-snapshot baseline */
        return true;                  /* durable advance: reset the budget */
    }
    return false;                     /* frozen: budget exhausts -> bounded page */
}

/* Surface the SAME structured owner-run recipe shielded_gap_remedy_controller.c
 * reports (single source of truth, read back via its JSON dumper) as the
 * terminal option, optionally with the exact named need.  named_height < 0
 * prints the copy-prove-deferral variant. */
static void selfheal_log_named_recipe(int64_t named_height)
{
    struct json_value sgr;
    json_init(&sgr);
    bool have_sgr = shielded_gap_remedy_dump_state_json(&sgr, NULL);
    const char *summary = "";
    const char *copy_step = "";
    const char *import_cmd = "";
    if (have_sgr) {
        const struct json_value *remedy = json_get(&sgr, "remedy");
        summary = json_get_str(json_get(remedy, "summary"));
        copy_step = json_get_str(json_get(remedy, "copy_prove_step"));
        import_cmd = json_get_str(json_get(remedy, "import_command"));
    }
    if (!summary[0])
        summary = "import the complete Sprout+Sapling anchor and nullifier "
                  "history (-import-complete-shielded) then reboot";
    if (!copy_step[0])
        copy_step = "tools/scripts/import-copy-prove.sh";
    if (!import_cmd[0])
        import_cmd = "zclassic23 -import-complete-shielded=<zclassicd-datadir>";
    if (named_height >= 0)
        LOG_WARN(SSL_SUBSYS,
                 "[condition:%s] Rung C: sovereign self-heal cannot proceed — "
                 "first missing local body/artifact at h=%lld. Terminal owner "
                 "option: %s | copy-prove FIRST: %s | then: %s "
                 "(full detail: dumpstate shielded_gap_remedy)",
                 SSL_COND_NAME, (long long)named_height, summary, copy_step,
                 import_cmd);
    else
        LOG_WARN(SSL_SUBSYS,
                 "[condition:%s] NAMED REMEDY on a copy-prove -COPY- datadir "
                 "(sovereign auto-heal deferred to the operator): %s | "
                 "copy-prove FIRST: %s | then: %s",
                 SSL_COND_NAME, summary, copy_step, import_cmd);
    json_free(&sgr);
}

/* Rung A (nullifier half): drive the EXISTING populate-only walker over local
 * bodies (nullifier_backfill_service_run — bounded, resumable, self-
 * terminating, clears utxo_apply.nullifier_backfill_gap on completion).  Sets
 * *first_missing to the exact blocked height on a missing local body.  Returns
 * true iff it completed or made durable progress (the caller returns OK). */
static bool rungA_nullifier_rederive(sqlite3 *db, struct main_state *ms,
                                     int64_t *first_missing)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        LOG_WARN(SSL_SUBSYS,
                 "[condition:%s] Rung A(nullifier): no open node.db — cannot "
                 "re-derive here; falling through", SSL_COND_NAME);
        return false;
    }
    const char *datadir = agent_runtime_context_datadir();
    struct nullifier_backfill_config cfg = {
        .main = ms,
        .ndb = ndb,
        .progress_db = db,
        .datadir = (datadir && datadir[0]) ? datadir : NULL,
    };
    struct nullifier_backfill_report rep;
    memset(&rep, 0, sizeof(rep));
    struct zcl_result r = nullifier_backfill_service_run(&cfg, &rep);
    if (r.ok) {
        LOG_WARN(SSL_SUBSYS,
                 "[condition:%s] Rung A(nullifier): populate-only re-derive %s "
                 "(range=[%lld,%lld) scanned=%lld) — consensus-neutral",
                 SSL_COND_NAME,
                 rep.completed ? "COMPLETE" : "advanced",
                 (long long)rep.start_height,
                 (long long)rep.target_exclusive,
                 (long long)rep.blocks_scanned);
        return true;
    }
    if (r.code == -48) {   /* missing validated local body: name it for Rung C */
        if (first_missing)
            *first_missing = rep.next_height;
        LOG_WARN(SSL_SUBSYS,
                 "[condition:%s] Rung A(nullifier): blocked at missing local "
                 "body h=%lld (scanned=%lld) — falling to Rung B/C",
                 SSL_COND_NAME, (long long)rep.next_height,
                 (long long)rep.blocks_scanned);
        /* Any partial advance is captured by the durable resume cursor and
         * seen by .progressing; do not claim OK on a blocked run. */
        return false;
    }
    LOG_WARN(SSL_SUBSYS,
             "[condition:%s] Rung A(nullifier): re-derive error code=%d %s — "
             "falling to Rung B/C",
             SSL_COND_NAME, r.code, r.message);
    return false;
}

enum condition_remedy_result shielded_selfheal_run_named_remedy(void)
{
    /* SEPARATE sovereign authorization — NOT the borrowed-import gate.  On a
     * -COPY- copy-prove datadir defer to the operator (surface + FAILED). */
    if (!shielded_selfheal_sovereign_authorized()) {
        selfheal_log_named_recipe(-1);
        return COND_REMEDY_FAILED;
    }

    sqlite3 *db = progress_store_db();
    struct main_state *ms = sync_monitor_main_state();
    if (!db || !ms)
        return COND_REMEDY_SKIP;   // raw-return-ok:store/state not wired this tick

    enum shielded_gap_kind gap = shielded_gap_remedy_classify();
    int64_t nullifier_missing = -1;

    /* RUNG A (nullifier half) — in-process populate-only re-derive. */
    if (gap == SHIELDED_GAP_NULLIFIER_ONLY &&
        rungA_nullifier_rederive(db, ms, &nullifier_missing))
        return COND_REMEDY_OK;

    /* RUNG A (anchor half) — arm the from-anchor/genesis refold (the sovereign
     * local-body re-derive of the CUMULATIVE Sapling anchor tree + nullifiers),
     * REUSING the existing tier2 machinery: its deepest rung is exactly
     * rung_refold_from_anchor_default (boot_auto_refold_request + supervised
     * respawn with the TERMINAL budget).  Gated on a reachable verified anchor
     * artifact so the boot reset does not FATAL-refuse; the refold's own
     * boot-time body-span gate (boot_refold_body_span_contiguous -> refold.
     * body_gap) names any missing body, so arming is self-terminating. */
    if ((gap == SHIELDED_GAP_ANCHOR_ONLY || gap == SHIELDED_GAP_BOTH) &&
        boot_refold_from_anchor_artifact_available(app_runtime_node_db(), NULL)) {
        sticky_escalator_note_stall("shielded-selfheal-anchor-rederive");
        LOG_WARN(SSL_SUBSYS,
                 "[condition:%s] Rung A(anchor): armed the from-anchor refold — "
                 "sovereign local-body re-derive of the Sapling anchors + "
                 "nullifiers (supervised respawn re-folds)", SSL_COND_NAME);
        return COND_REMEDY_OK;   /* armed; the fresh boot re-seeds + re-folds */
    }

    /* RUNG B — checkpoint-verified install-on-next-boot (bodies absent / no
     * re-derive base).  Autodetect a ROM-matching <datadir>/bundles/<name>.sqlite
     * and arm the durable request via the landed keystone; the atomic installer
     * is fail-closed and rolls back on any anomaly to the safe positive-cursor
     * wedge.  Never invents a parallel cure. */
    const char *datadir = agent_runtime_context_datadir();
    if (datadir && datadir[0]) {
        char *bundle = boot_autodetect_consensus_bundle(datadir);
        /* Gate on the checkpoint header's Equihash solution being durably
         * available before arming: boot_install_bundle_consume burns
         * BOOT_INSTALL_BUNDLE_MAX BEFORE the install with no refund on a
         * solutionless retriable defer, so 3 deferred boots exhaust the budget and
         * the request is never re-armed (cure permanently dead). Mirror
         * checkpoint_bundle_install_ready's gate — the sibling
         * checkpoint_header_solution_repair peer-fetches + persists the solution
         * first. This ladder is disabled on '-COPY-' datadirs, so the burn is
         * INVISIBLE to copy-proof and can only manifest live. */
        if (bundle) {
            const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
            bool solution_ready = false;
            if (cp) {
                struct uint256 cph;
                memcpy(cph.data, cp->block_hash, 32);
                solution_ready =
                    checkpoint_header_solution_available(cp->height, &cph);
            }
            if (!solution_ready) {
                LOG_INFO(SSL_SUBSYS,
                         "[condition:%s] Rung B: staged bundle %s but the "
                         "checkpoint header solution is not yet durable — NOT "
                         "arming (would burn the bounded install budget on a "
                         "solutionless defer); waiting on "
                         "checkpoint_header_solution_repair",
                         SSL_COND_NAME, bundle);
                free(bundle);
                bundle = NULL;
            }
        }
        if (bundle) {
            int armed = boot_install_bundle_request(datadir, bundle);
            LOG_WARN(SSL_SUBSYS,
                     "[condition:%s] Rung B: %s checkpoint-verified install-on-"
                     "next-boot of %s (atomic keystone installer; rolls back on "
                     "any anomaly)",
                     SSL_COND_NAME,
                     armed > 0 ? "ARMED"
                               : armed == BOOT_INSTALL_BUNDLE_TERMINAL
                                     ? "budget-exhausted (not re-arming)"
                                     : "failed to arm",
                     bundle);
            free(bundle);
            if (armed > 0)
                return COND_REMEDY_OK;   /* install runs on the next boot */
            /* terminal/failed: fall through to name the need + page */
        }
    }

    /* RUNG C — self-terminating named need.  Name the EXACT first missing body
     * height (the nullifier walker's blocked height and/or the blocks-projection
     * hole), surface the terminal owner-run import option, and let the bounded
     * page fire.  FAILED (not SKIP): the condition IS engaged.  The .progressing
     * hook resets the budget ONLY while the heal cursor advances, so a genuinely
     * frozen node pages in bounded time and never re-spins the identical
     * no-op. */
    int64_t body_missing = -1;
    {
        struct node_db *ndb = app_runtime_node_db();
        int max_h = active_chain_height(&ms->chain_active);
        int mh = -1;
        if (ndb && app_runtime_node_db_handle_open(ndb) && max_h >= 0 &&
            db_block_first_missing_connected_height(ndb, max_h, &mh) && mh >= 0)
            body_missing = mh;
    }
    int64_t need = shielded_selfheal_named_need(nullifier_missing, body_missing);
    atomic_store(&g_selfheal_named_height, need);
    selfheal_log_named_recipe(need);
    return COND_REMEDY_FAILED;
}
