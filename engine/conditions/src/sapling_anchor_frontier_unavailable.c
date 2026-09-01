/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sapling_anchor_frontier_unavailable -- auto-terminating cure for the empty
 * Sapling anchor-frontier stall.
 *
 * The defect (live P0): a snapshot/refold seed runs
 * anchor_kv_reset_mark_empty_below_in_tx with a nonzero activation_cursor but
 * WITHOUT an initial frontier row, so the first
 * shielded-output block above the seed finds an empty sapling_anchors table.
 * anchor_kv_latest_tree then falls through to the activation gate and returns
 * HISTORY_INCOMPLETE (engine/modules/storage/src/anchor_kv.c), fold_sapling fails closed
 * (engine/jobs/src/utxo_apply_anchors.c), and utxo_apply holds its cursor forever
 * behind the blocker utxo_apply.anchor_backfill_gap with no escape action.
 *
 * Fail-closed is consensus-correct.  This condition is the missing remedy.
 * ROUTING: the EMPTY_TABLE birth defect is attempted first (tier1/1b below)
 * even when the named-remedy predicate also holds — the cold-import seed
 * heal leaves the nullifier blocker set alongside the anchor reset, and the
 * ladder cannot supply an initial frontier row (2026-08-01 live wedge).
 *   tier 1 — seed a HEADER-VERIFIED initial frontier from the flat-file sapling
 *            checkpoint the node already maintains (boot.c load path).  The
 *            frontier's own root MUST equal the block's hashFinalSaplingRoot at
 *            the checkpoint height, and the checkpoint height must sit in the
 *            safe window [activation, stall_height) — otherwise refuse.
 *   tier 1b— BORROWED frontier from the co-located, LIVE
 *             zclassicd; a matching block/header locates it but does not
 *             consensus-bind shielded state
 *            zclassicd chainstate LevelDB ($HOME/.zclassic/chainstate; same
 *            trust model as the legacy bootstrap).  Take a point-in-time copy
 *            (never touch the live dir), look up the Sapling anchor tree keyed
 *            by header(H*).hashFinalSaplingRoot — the exact post-H* frontier the
 *            fold consumes next — VERIFY the borrowed tree's own root equals
 *            that PoW-committed header field (fail-closed, double-verified via
 *            anchor_kv_seed_frontier_row), then seed at H*.  Attempt-bounded
 *            (the copy is heavy); on any failure the ladder continues to tier2/3
 *            unchanged.  The borrow is a stopgap — tier2's sovereign anchor
 *            artifact remains the terminal cure.
 *   tier 2 — no verified frontier available: arm the bounded refold + supervised
 *            respawn via the sticky escalator's terminal rung (which owns the
 *            boot_auto_refold_request + respawn machinery and its TERMINAL
 *            budget), gated on a reachable verified anchor artifact.
 *   tier 3 — no verified frontier AND no refold artifact, OR a genuine
 *            below-cursor historical gap: leave the honest owner-gated permanent
 *            blocker and page the operator.  Never fake-resolve.
 *
 * NAMED REMEDY (not seed-curable): SAPLING_ANCHOR_GAP_HISTORICAL (rows exist,
 * a specific below-cursor root is absent) and/or a standalone nullifier gap
 * (utxo_apply.nullifier_backfill_gap).  Seeding a single frontier row cannot
 * supply a full historical anchor+nullifier set, so tier1/1b/2 do NOT apply.
 * Instead the remedy dispatches to the SOVEREIGN self-heal ladder (Move 2a,
 * shielded_selfheal_run_named_remedy in shielded_selfheal_ladder.c) — a
 * bounded, self-terminating, auto-executing 3-rung ladder that RE-DERIVES
 * proven state (Rung A) or CHECKPOINT-verifies (Rung B) or NAMES the exact
 * need (Rung C); it never forges, borrows-unverified, or relaxes a check (see
 * the ladder contract in sapling_anchor_frontier_unavailable.h and Move 2a):
 *   Rung A — sovereign re-derive from LOCAL block bodies (preferred): the
 *            in-process nullifier_backfill_service_run() populate-only walker
 *            for a standalone nullifier gap, or the from-anchor/genesis refold
 *            (arm + supervised respawn) that recomputes the SAME anchors the
 *            fold would for an anchor gap.  Consensus-neutral.
 *   Rung B — checkpoint-verified install (bodies absent): arm the durable
 *            install-on-next-boot request (boot_install_bundle_request) against
 *            a ROM-matching <datadir>/bundles/<name>.sqlite; the atomic keystone
 *            installer is fail-closed and rolls back on any anomaly.
 *   Rung C — self-terminating named need: name the EXACT first missing body
 *            height, surface the terminal owner-run import option, and let the
 *            bounded page fire.  The .progressing hook resets the attempt budget
 *            ONLY while the durable heal cursor advances, so a genuinely frozen
 *            node pages in bounded time and never re-spins the identical no-op.
 * The AUTO path is authorized by a SEPARATE gate (shielded_selfheal_sovereign_
 * authorized), distinct from the borrowed-import containment
 * (shielded_gap_remedy_eval_containment / auto_execute), which stays owner-gated
 * and UNTOUCHED — a -COPY- copy-prove datadir defers to the operator.  The
 * witness for this class requires BOTH the named blocker(s) clearing AND H*
 * climbing past the stall height, so a stray tick cannot be mistaken for the
 * cure having actually landed.
 *
 * CONSENSUS PARITY: the sapling_frontier_mismatch reject path is untouched; a
 * mismatched frontier is never written (anchor_kv_seed_frontier_row re-verifies
 * the root and refuses); activation_cursor is never forced to 0 by this
 * condition (only the owner-run importer flips it).  The birth-defect witness
 * clear-edge is H* climbing past the stall height captured at detect; the
 * named-remedy witness additionally requires the relevant blocker(s) gone. */

#include "conditions/sapling_anchor_frontier_unavailable.h"

#include "conditions/shielded_selfheal_ladder.h"
#include "config/boot.h"
#include "config/runtime.h"
#include "controllers/shielded_gap_remedy_controller.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_history_hold.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "json/json.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "services/utxo_recovery_service.h"
#include "storage/anchor_kv.h"
#include "storage/chainstate_legacy_reader.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/file_tree_ops.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SAFU_COND_NAME SAPLING_ANCHOR_FRONTIER_CONDITION_NAME
#define SAFU_SUBSYS "condition"

/* H* captured at the rising edge of an episode; the witness clears only when H*
 * climbs strictly past it.  -1 = no active episode. */
static _Atomic int32_t g_hstar_at_detect = -1;

/* Which flavour of gap is the CURRENT active episode, captured at the same
 * rising edge as g_hstar_at_detect.  Distinguishes the two witness contracts:
 * a birth-defect episode clears purely on H* climbing (tier1/1b/2 never touch
 * activation_cursor, so the blocker can legitimately outlive the cure); a
 * named-remedy episode additionally requires the blocker(s) named below to be
 * gone, since only the owner-run import flips activation_cursor to 0 and
 * clears them. */
enum safu_episode_kind {
    SAFU_EPISODE_NONE = 0,
    SAFU_EPISODE_BIRTH_DEFECT = 1,
    SAFU_EPISODE_NAMED_REMEDY = 2,
};
static _Atomic int g_episode_kind = SAFU_EPISODE_NONE;

/* Which typed blocker(s) were present at the named-remedy episode's rising
 * edge — the witness only requires clearing the ones that were actually
 * named, not blockers this episode never observed. */
static _Atomic bool g_anchor_gap_at_detect = false;
static _Atomic bool g_nullifier_gap_at_detect = false;

/* Tier-1b borrow is heavy (a point-in-time copy of zclassicd's chainstate), so
 * cap borrow attempts per process.  Once exhausted the remedy falls straight
 * through to tier2/tier3. */
#define SAFU_TIER1B_MAX_ATTEMPTS 2
static _Atomic int g_tier1b_attempts;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
static _Atomic int g_test_tier1_attempts;
#endif

enum sapling_anchor_gap_class sapling_anchor_frontier_classify(sqlite3 *db)
{
    if (!db)
        return SAPLING_ANCHOR_GAP_NONE;

    int64_t activation = 0;
    bool found = false;
    if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &activation,
                                     &found))
        return SAPLING_ANCHOR_GAP_NONE;   /* store error: do not claim curable */
    /* From-genesis store (or unadopted): an empty table is COMPLETE, not a gap
     * (anchor_kv_latest_tree returns the empty frontier as FOUND). */
    if (!found || activation <= 0)
        return SAPLING_ANCHOR_GAP_NONE;

    bool empty = false;
    if (!anchor_kv_table_is_empty(db, ANCHOR_POOL_SAPLING, &empty))
        return SAPLING_ANCHOR_GAP_NONE;

    if (!empty)
        /* Rows exist: any residual gap is a specific below-cursor historical
         * root miss (point-lookup HISTORY_INCOMPLETE), which seeding cannot
         * cure — owner-gated backfill territory. */
        return SAPLING_ANCHOR_GAP_HISTORICAL;

    /* Empty table + activation>0: confirm the actual stall symptom before
     * claiming the curable birth defect. */
    struct incremental_merkle_tree t;
    enum anchor_kv_lookup_result lr =
        anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &t, NULL, NULL);
    if (lr != ANCHOR_KV_HISTORY_INCOMPLETE)
        return SAPLING_ANCHOR_GAP_NONE;

    return SAPLING_ANCHOR_GAP_EMPTY_TABLE;
}

static bool detect_sapling_anchor_frontier(void)
{
    sqlite3 *db = progress_store_db();
    struct main_state *ms = sync_monitor_main_state();
    if (!db || !ms)
        return false;

    bool anchor_gap = blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
    bool nullifier_gap = blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    if (!anchor_gap && !nullifier_gap)
        return false;  // raw-return-ok:healthy no-detect path on every engine tick, not an error

    enum sapling_anchor_gap_class cls = sapling_anchor_frontier_classify(db);
    bool birth_defect = anchor_gap && cls == SAPLING_ANCHOR_GAP_EMPTY_TABLE;
    /* NAMED REMEDY: a genuine below-cursor historical anchor gap and/or a
     * standalone nullifier gap.  Not seed-curable by tier1/1b/2 — the remedy
     * dispatches to the SOVEREIGN self-heal ladder (Move 2a,
     * shielded_selfheal_run_named_remedy): re-derive from local bodies (Rung A),
     * else checkpoint-verified install (Rung B), else name the exact need (Rung
     * C).  The BORROWED -import-complete-shielded stays the owner's terminal
     * option, never auto-run from here. */
    bool named_remedy = (anchor_gap && cls == SAPLING_ANCHOR_GAP_HISTORICAL) ||
                         nullifier_gap;
    if (!birth_defect && !named_remedy)
        return false;  // raw-return-ok:blocker present but not a class this condition names, e.g. read error

    /* Must be genuinely behind: H* pinned below the header tip means there is
     * more to fold and the fold is stuck (not simply at tip with nothing to
     * apply).  H* = the provable reducer tip = utxo_apply's held height. */
    int32_t hstar = reducer_frontier_provable_tip_cached();
    int header_tip = active_chain_height(&ms->chain_active);
    if (hstar < 0 || header_tip <= hstar)
        return false;

    /* Capture the at-detect baseline ONCE, at the rising edge (detect runs
     * before the engine flips currently_active).  Prefer birth-defect when
     * both are somehow true at once (e.g. a dual anchor+nullifier wedge where
     * the anchor half is still the auto-curable empty-table case) since it is
     * the one this condition can actually resolve itself; the nullifier half
     * re-detects as a fresh named-remedy episode once the anchor half clears. */
    struct condition_runtime_snapshot snap;
    bool already_active =
        condition_engine_get_registered_snapshot(SAFU_COND_NAME, &snap) &&
        snap.currently_active;
    if (!already_active) {
        atomic_store(&g_hstar_at_detect, hstar);
        atomic_store(&g_episode_kind, birth_defect ? SAFU_EPISODE_BIRTH_DEFECT
                                                    : SAFU_EPISODE_NAMED_REMEDY);
        atomic_store(&g_anchor_gap_at_detect, anchor_gap);
        atomic_store(&g_nullifier_gap_at_detect, nullifier_gap);
        /* Fresh episode: re-arm the self-heal ladder's progress baseline +
         * named need so .progressing measures advance from THIS episode's
         * start. */
        shielded_selfheal_reset_episode();
    }
    return true;
}

/* Tier 1: seed a header-verified initial frontier from the flat-file sapling
 * checkpoint.  Returns true only if a verified frontier was written. */
static bool tier1_seed_verified_frontier(sqlite3 *db, struct main_state *ms,
                                         int64_t stall_height)
{
    const char *ckpt_path = sapling_checkpoint_path();
    if (!ckpt_path)
        return false;

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    int64_t ckpt_h = -1;
    uint8_t ckpt_block_hash[32] = {0};
    if (!sapling_tree_load_checkpoint(&tree, &ckpt_h, ckpt_block_hash,
                                      ckpt_path))
        return false;   /* absent/corrupt: fall to tier 2 */

    int64_t activation = 0;
    bool found = false;
    if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &activation,
                                     &found) || !found)
        return false;

    /* Safe window: the frontier at ckpt_h equals the frontier at stall_height-1
     * ONLY when no sapling outputs occurred in (ckpt_h, stall_height).  Since
     * stall_height is the FIRST shielded block at/after the seed cursor, that
     * holds exactly for activation <= ckpt_h < stall_height.  Outside the
     * window a seed could thread a wrong frontier — refuse and let tier 2/3 run
     * (fold_sapling would fail closed on a mismatch anyway, but we never even
     * attempt an out-of-window seed). */
    if (ckpt_h < activation || ckpt_h >= stall_height) {
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1 refused: sapling checkpoint h=%lld "
                 "outside safe window [%lld,%lld)",
                 SAFU_COND_NAME, (long long)ckpt_h, (long long)activation,
                 (long long)stall_height);
        return false;
    }

    const struct block_index *bi = active_chain_at(&ms->chain_active,
                                                   (int)ckpt_h);
    if (!bi)
        return false;
    static const uint8_t zeros32[32] = {0};
    if (memcmp(bi->hashFinalSaplingRoot.data, zeros32, 32) == 0) {
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1 refused: header hashFinalSaplingRoot "
                 "unknown at h=%lld — cannot verify",
                 SAFU_COND_NAME, (long long)ckpt_h);
        return false;
    }

    /* Fail-closed header binding: same verify-then-trust decision boot uses. */
    struct uint256 ckpt_root;
    incremental_tree_root(&tree, &ckpt_root);
    const struct block_index *ctip = active_chain_tip(&ms->chain_active);
    bool exp_hash_known = bi->phashBlock != NULL;
    enum sapling_ckpt_verdict v = sapling_ckpt_verify_binding(
        ckpt_h, &ckpt_root, ckpt_block_hash, ctip ? ctip->nHeight : -1,
        exp_hash_known ? bi->phashBlock->data : NULL, exp_hash_known,
        &bi->hashFinalSaplingRoot, true);
    if (v != SAPLING_CKPT_OK) {
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1 refused: checkpoint failed header "
                 "binding at h=%lld (%s)",
                 SAFU_COND_NAME, (long long)ckpt_h, sapling_ckpt_verdict_str(v));
        return false;
    }

    /* Serialize the single-statement write behind the shared progress.kv lock
     * (condition-engine tick thread, not the reducer drive — lock-order-safe).
     * anchor_kv_seed_frontier_row re-verifies root == header root and writes
     * nothing on any mismatch. */
    progress_store_tx_lock();
    bool ok = anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING, &tree,
                                          ckpt_h, &bi->hashFinalSaplingRoot);
    progress_store_tx_unlock();
    if (ok)
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1 SEEDED verified Sapling frontier at "
                 "h=%lld (root == header) — fold resumes at h=%lld",
                 SAFU_COND_NAME, (long long)ckpt_h, (long long)stall_height);
    return ok;
}

/* Derive the active datadir from the flat-file checkpoint path
 * (<datadir>/sapling_tree_ckpt.dat) so the borrow copy lands beside it. */
static bool tier1b_datadir(char *out, size_t cap)
{
    const char *ck = sapling_checkpoint_path();
    if (!ck)
        return false;  // raw-return-ok:no checkpoint path configured — caller falls through
    const char *slash = strrchr(ck, '/');
    if (!slash || slash == ck)
        return false;  // raw-return-ok:unexpected relative path — caller falls through
    size_t len = (size_t)(slash - ck);
    if (len == 0 || len >= cap)
        return false;  // raw-return-ok:path too long for buffer — caller falls through
    memcpy(out, ck, len);
    out[len] = '\0';
    return true;
}

/* Tier 1b: borrow the exact post-H* Sapling frontier from the co-located LIVE
 * zclassicd chainstate, verify it against our own PoW-committed header, and
 * seed it.  Returns true only if a header-verified frontier was written. */
static bool tier1b_borrow_verified_frontier(sqlite3 *db, struct main_state *ms,
                                            int64_t stall_height)
{
    if (atomic_load(&g_tier1b_attempts) >= SAFU_TIER1B_MAX_ATTEMPTS)
        return false;   /* exhausted: fall through to tier2/tier3 */

    /* Borrow source: the co-located zclassicd chainstate (same path the legacy
     * import uses).  Absent => no borrow possible. */
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;
    char cs_path[1024];
    int n = snprintf(cs_path, sizeof(cs_path), "%s/.zclassic/chainstate", home);
    if (n < 0 || (size_t)n >= sizeof(cs_path))
        return false;
    struct stat st;
    if (stat(cs_path, &st) != 0)
        return false;

    /* Safe-window floor + the exact frontier height the fold consumes next.
     * We seed ONLY at H* = stall_height-1: that frontier (== the tree after
     * block H*) is precisely what fold_sapling needs at stall_height.  Seeding
     * any lower would skip the leaves added between there and H* and the fold
     * would fail closed on the mismatch. */
    int64_t activation = 0;
    bool found = false;
    if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &activation,
                                     &found) || !found)
        return false;
    int64_t seed_h = stall_height - 1;
    if (seed_h < activation || seed_h >= stall_height)
        return false;

    const struct block_index *bi = active_chain_at(&ms->chain_active,
                                                   (int)seed_h);
    if (!bi)
        return false;
    static const uint8_t zeros32[32] = {0};
    if (memcmp(bi->hashFinalSaplingRoot.data, zeros32, 32) == 0) {
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1b refused: header hashFinalSaplingRoot "
                 "unknown at H*=%lld — cannot verify a borrow",
                 SAFU_COND_NAME, (long long)seed_h);
        return false;
    }

    char datadir[1024];
    if (!tier1b_datadir(datadir, sizeof(datadir)))
        return false;  // raw-return-ok:no writable datadir for the borrow copy — falls through to tier2/3
    char import_path[1200];
    n = snprintf(import_path, sizeof(import_path), "%s/anchor_borrow_tmp",
                 datadir);
    if (n < 0 || (size_t)n >= sizeof(import_path))
        return false;

    /* Count this heavy attempt up front so a repeatedly-failing borrow is
     * bounded even when the copy itself fails. */
    atomic_fetch_add(&g_tier1b_attempts, 1);

    /* Point-in-time copy — zclassicd holds the LevelDB LOCK, so NEVER open the
     * live dir directly.  A torn copy is refused by the helper. */
    struct zcl_result cpres =
        utxo_recovery_copy_chainstate_stable(cs_path, import_path);
    if (!cpres.ok) {
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1b: point-in-time chainstate copy failed "
                 "(%s) — falling through",
                 SAFU_COND_NAME, cpres.message);
        return false;
    }
    /* Remove the copied LOCK so we can open the borrow read-only. */
    char tmp_lock[1300];
    snprintf(tmp_lock, sizeof(tmp_lock), "%s/LOCK", import_path);
    unlink(tmp_lock);

    bool seeded = false;
    void *csh = NULL;
    if (chainstate_legacy_open(import_path, &csh)) {
        struct incremental_merkle_tree tree;
        enum chainstate_anchor_result r = chainstate_legacy_get_sapling_anchor(
            csh, &bi->hashFinalSaplingRoot, &tree);
        if (r == CHAINSTATE_ANCHOR_FOUND) {
            /* Verified borrow.  Seed under the shared progress.kv lock (tick
             * thread, not the reducer drive — lock-order-safe).
             * anchor_kv_seed_frontier_row re-verifies root == header root a
             * second time and writes nothing on any mismatch. */
            progress_store_tx_lock();
            seeded = anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING, &tree,
                                                 seed_h,
                                                 &bi->hashFinalSaplingRoot);
            progress_store_tx_unlock();
            if (seeded)
                LOG_WARN(SAFU_SUBSYS,
                         "[condition:%s] tier1b BORROWED a header-verified "
                         "Sapling frontier from zclassicd chainstate at H*=%lld "
                         "(root == PoW-committed hashFinalSaplingRoot) — fold "
                         "resumes at h=%lld [BORROWED stopgap; sovereign anchor "
                         "artifact remains the terminal cure]",
                         SAFU_COND_NAME, (long long)seed_h,
                         (long long)stall_height);
        } else {
            LOG_WARN(SAFU_SUBSYS,
                     "[condition:%s] tier1b refused: borrowed chainstate has no "
                     "VERIFIABLE frontier for header root at H*=%lld (result=%d) "
                     "— falling through",
                     SAFU_COND_NAME, (long long)seed_h, (int)r);
        }
        chainstate_legacy_close(csh);
    } else {
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1b: could not open borrowed chainstate copy "
                 "at %s — falling through",
                 SAFU_COND_NAME, import_path);
    }

    /* The borrow is read-once: remove the temp copy (mirrors the
     * utxo_recovery_restore.c cleanup for a zclassicd-LOCK copy). `rm -rf`
     * via the fd-based walker (no shell). */
    struct zcl_result rm = zcl_tree_remove(import_path);
    if (!rm.ok)
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier1b: temp borrow copy cleanup failed "
                 "for %s (non-fatal): %s",
                 SAFU_COND_NAME, import_path, rm.message);

    return seeded;
}

static enum condition_remedy_result remedy_sapling_anchor_frontier(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    sqlite3 *db = progress_store_db();
    struct main_state *ms = sync_monitor_main_state();
    if (!db || !ms)
        return COND_REMEDY_SKIP;

    enum sapling_anchor_gap_class cls = sapling_anchor_frontier_classify(db);

    /* EMPTY_TABLE birth defect FIRST, even when the named-remedy predicate
     * below also holds: the cold-import seed heal marks nullifier history
     * empty-below alongside the anchor reset, so the NF blocker is present in
     * almost every seed-boot episode — routing to the ladder on that disjunct
     * alone stranded a tier1-curable anchor wedge (the ladder's Rung A anchor
     * path only arms a refold respawn that the escalator's permanent-blocker
     * hold parks; it can never supply the initial frontier row).  Observed
     * live 2026-08-01 (anchor replay-canary): seed-boot at tip, both blockers
     * set, the flat-file checkpoint became root-verified minutes AFTER the
     * remedy attempts had latched at max_attempts.  Detect already records
     * this dual case as a birth-defect episode precisely because the anchor
     * half is the auto-curable one; the nullifier half re-detects as a fresh
     * named-remedy episode once the anchor half clears. */
    if (cls == SAPLING_ANCHOR_GAP_EMPTY_TABLE) {
        int32_t hstar_early = reducer_frontier_provable_tip_cached();
        if (hstar_early >= 0) {
            int64_t stall_early = (int64_t)hstar_early + 1;
#ifdef ZCL_TESTING
            atomic_fetch_add(&g_test_tier1_attempts, 1);
#endif
            if (tier1_seed_verified_frontier(db, ms, stall_early) ||
                tier1b_borrow_verified_frontier(db, ms, stall_early)) {
                /* The seed is only half the cure in-process: a GATE_HOLD on
                 * the stall block recorded an in-memory history-hold memo
                 * (utxo_apply_history_hold_record) that parks every later
                 * utxo_apply step while the anchor gap BLOCKER exists — and
                 * the blocker legitimately outlives the seed (the activation
                 * cursor stays >0 by design), so without this clear the fold
                 * never re-attempts the gate and H* never climbs; only a
                 * process restart used to drop the memo (2026-08-02 anchor
                 * replay-canary wedge at h=3202122, frontier seeded by
                 * tier1b 25 min prior).  Clearing is fail-closed-safe: the
                 * next step re-runs the shielded gate, which re-holds if the
                 * frontier were genuinely absent. */
                utxo_apply_history_hold_clear();
                return COND_REMEDY_OK;  /* witness (H* climb) confirms resume */
            }
        }
    }

    /* NAMED REMEDY class next: neither tier1 (checkpoint seed) nor
     * tier1b (borrowed frontier seed) nor tier2 (bounded refold) can supply a
     * full historical anchor+nullifier set — attempting them for a HISTORICAL
     * gap would be exactly the kind of downstream repair rung TENACITY I3
     * forbids for a gap only the write-time import can correctly fill. */
    if ((cls == SAPLING_ANCHOR_GAP_HISTORICAL &&
         blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID)) ||
        blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID))
        return shielded_selfheal_run_named_remedy();

    /* Re-confirm we still face the curable empty-table birth defect. */
    if (cls != SAPLING_ANCHOR_GAP_EMPTY_TABLE)
        return COND_REMEDY_SKIP;

    int32_t hstar = reducer_frontier_provable_tip_cached();
    if (hstar < 0)
        return COND_REMEDY_SKIP;
    int64_t stall_height = (int64_t)hstar + 1;

    /* Tier1/tier1b were already attempted above for this class (once per
     * remedy run — tier1b burns one of its per-process attempt cap slots on
     * each call, so a second pass here would halve the budget for no
     * information).  Fall through to the heavier tiers. */

    /* TIER 2 — arm the bounded refold + supervised respawn, but only if a
     * verified anchor artifact is reachable (else the boot reset FATAL-refuses).
     * sticky_escalator_note_stall arms the ladder whose DEEPEST rung is exactly
     * rung_refold_from_anchor_default (boot_auto_refold_request + respawn with
     * the TERMINAL budget) — reuse, do not duplicate. */
    if (boot_refold_from_anchor_artifact_available(app_runtime_node_db(), NULL)) {
        sticky_escalator_note_stall("sapling-anchor-frontier-unavailable");
        LOG_WARN(SAFU_SUBSYS,
                 "[condition:%s] tier2: no verified frontier at stall h=%lld — "
                 "armed the bounded refold-from-anchor ladder (self-respawn)",
                 SAFU_COND_NAME, (long long)stall_height);
        return COND_REMEDY_OK;   /* armed; the fresh boot re-seeds + re-folds */
    }

    /* TIER 3 — no verified frontier AND no refold artifact: leave the honest
     * owner-gated permanent blocker (utxo_apply_anchor_gap_blocker_refresh
     * already set it) and let the engine accrue attempts -> page the operator.
     * Never fake-resolve a genuinely-absent historical anchor. */
    LOG_WARN(SAFU_SUBSYS,
             "[condition:%s] tier3: no verified frontier and no reachable "
             "refold artifact at stall h=%lld — owner-gated (provide the "
             "SHA3-checkpoint-bound anchor snapshot or a full-history refold)",
             SAFU_COND_NAME, (long long)stall_height);
    return COND_REMEDY_FAILED;
}

static bool witness_sapling_anchor_frontier(int64_t target_at_detect)
{
    /* The engine passes a wall-clock timestamp here, not a height — ignore it
     * and read our own captured baseline. */
    (void)target_at_detect;
    int32_t base = atomic_load(&g_hstar_at_detect);
    if (base < 0)
        return false;
    int32_t now = reducer_frontier_provable_tip_cached();
    if (now < 0)
        return false;                 /* read failure = not-yet-cleared */
    bool climbed = now > base;         /* H* climbed past the stall */

    /* Birth-defect clear-edge: tier1/1b/2 never touch activation_cursor, so
     * the anchor gap blocker can legitimately outlive the cure — H* climbing
     * is the sole, sufficient signal (unchanged from the original design). */
    if (atomic_load(&g_episode_kind) != SAFU_EPISODE_NAMED_REMEDY)
        return climbed;

    /* Named-remedy clear-edge: only the owner-run `-import-complete-shielded`
     * flips activation_cursor to 0, which is what actually clears these
     * blockers (utxo_apply_anchor_gap_blocker_refresh /
     * utxo_apply_nullifier_gap_blocker_refresh, called from the importer).
     * Require BOTH the blocker(s) this episode named gone AND H* climbing —
     * a stray tick where H* happens to advance without the import having run
     * must NOT be mistaken for the wedge clearing. */
    bool anchor_cleared = !atomic_load(&g_anchor_gap_at_detect) ||
                         !blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
    bool nullifier_cleared = !atomic_load(&g_nullifier_gap_at_detect) ||
                            !blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    return climbed && anchor_cleared && nullifier_cleared;
}

/* TL-1 REFRESH-ONLY progress signal for the sovereign self-heal ladder — a thin
 * wrapper delegating to the ladder TU (shielded_selfheal_progressing), gated to
 * the NAMED-REMEDY episode (the birth-defect tiers clear purely on the H*
 * witness).  A true return RESETS the attempt budget WITHOUT clearing so a
 * multi-round heal never false-pages; a frozen heal cursor still exhausts the
 * budget and pages in bounded time. */
static bool progressing_sapling_anchor_frontier(int64_t target_at_detect)
{
    (void)target_at_detect;
    return shielded_selfheal_progressing(
        atomic_load(&g_episode_kind) == SAFU_EPISODE_NAMED_REMEDY);
}

static bool detail_sapling_anchor_frontier(struct json_value *out)
{
    if (!out)
        return false;
    sqlite3 *db = progress_store_db();
    int cls = db ? (int)sapling_anchor_frontier_classify(db)
                 : (int)SAPLING_ANCHOR_GAP_NONE;
    bool ok = json_push_kv_int(out, "gap_class", cls) &&
              json_push_kv_int(out, "hstar_at_detect",
                               atomic_load(&g_hstar_at_detect)) &&
              json_push_kv_int(out, "episode_kind", atomic_load(&g_episode_kind)) &&
              json_push_kv_bool(out, "gap_blocker_present",
                                blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID)) &&
              json_push_kv_bool(out, "nullifier_gap_blocker_present",
                                blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID)) &&
              /* Move 2a self-heal surface: the exact height Rung C last named as
               * the missing need (-1 = none), and the sovereign auto-path
               * authorization (distinct from the borrowed-import containment
               * below). */
              json_push_kv_int(out, "selfheal_named_height",
                               shielded_selfheal_last_named_height()) &&
              json_push_kv_bool(out, "selfheal_sovereign_authorized",
                                shielded_selfheal_sovereign_authorized());
    if (!ok)
        return false;

    /* When a NAMED REMEDY applies (genuine historical anchor gap and/or a
     * standalone nullifier gap), attach the same structured, contained
     * recipe the shielded_gap_remedy dumper reports — directly on THIS
     * condition's typed surface, so an operator polling `condition_engine`
     * sees the actionable cure without a second lookup. Nested object: never
     * call json_set_object() on `out` itself (it would wipe the fields
     * pushed above). */
    if (shielded_gap_remedy_classify() != SHIELDED_GAP_NONE) {
        struct json_value sgr;
        json_init(&sgr);
        if (shielded_gap_remedy_dump_state_json(&sgr, NULL))
            json_push_kv(out, "shielded_gap_remedy", &sgr);
        json_free(&sgr);
    }
    return true;
}

static struct condition c_sapling_anchor_frontier_unavailable = {
    .name = SAFU_COND_NAME,
    .severity = COND_CRITICAL,
    .poll_secs = 10,
    .backoff_secs = 30,
    /* Bounded: after this many un-witnessed remedies the engine pages the
     * operator (tier 3 is the honest terminal for a genuinely-absent frontier).
     * Tier 2 respawns the process, so it does not accrue attempts here. */
    .max_attempts = 5,
    /* Continue-with-cooldown (sticky-node plan #7): the remedy's inputs are
     * produced by slower background machinery — the deferred sapling-tree
     * rebuild that makes the flat-file checkpoint root-verified (~10 min on a
     * 3.1M-header import boot), and P2P bodies still landing at tip.  Five
     * remedy attempts at poll/backoff cadence exhaust in ~3 min, far sooner
     * than those prerequisites, and the legacy latch then stranded a curable
     * wedge forever (observed live 2026-08-01: checkpoint became valid 2 min
     * after operator_needed).  Re-arm every 5 min instead: remedy runs are
     * idempotent (tier1 fail-closed, tier1b capped per-process, Rung C a
     * no-op log), the operator page still fires once per episode, and a
     * genuinely-absent frontier keeps paging on the age ladder. */
    .cooldown_secs = 300,
    .cooldown_max_rearms = 0,
    .detect = detect_sapling_anchor_frontier,
    .remedy = remedy_sapling_anchor_frontier,
    .witness = witness_sapling_anchor_frontier,
    /* TL-1: keep the bounded budget from false-paging a multi-round sovereign
     * self-heal (Rung A chunked backfill / a refold or install landing across
     * more rounds than max_attempts) while it makes durable, resumable
     * progress; a genuinely frozen heal still exhausts the budget and pages. */
    .progressing = progressing_sapling_anchor_frontier,
    .detail = detail_sapling_anchor_frontier,
    .witness_window_secs = 120,
};

void register_sapling_anchor_frontier_unavailable(void)
{
    (void)condition_register(&c_sapling_anchor_frontier_unavailable);
}

#ifdef ZCL_TESTING
void sapling_anchor_frontier_test_reset(void)
{
    atomic_store(&g_hstar_at_detect, -1);
    atomic_store(&g_episode_kind, SAFU_EPISODE_NONE);
    atomic_store(&g_anchor_gap_at_detect, false);
    atomic_store(&g_nullifier_gap_at_detect, false);
    atomic_store(&g_tier1b_attempts, 0);
    shielded_selfheal_reset_episode();
    atomic_store(&g_test_remedy_calls, 0);
    atomic_store(&g_test_tier1_attempts, 0);
}

int sapling_anchor_frontier_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

int sapling_anchor_frontier_test_tier1_attempts(void)
{
    return atomic_load(&g_test_tier1_attempts);
}

void sapling_anchor_frontier_test_force_named_episode(void)
{
    atomic_store(&g_episode_kind, SAFU_EPISODE_NAMED_REMEDY);
    shielded_selfheal_reset_episode();
}

bool sapling_anchor_frontier_test_progressing(void)
{
    return progressing_sapling_anchor_frontier(0);
}
#endif
