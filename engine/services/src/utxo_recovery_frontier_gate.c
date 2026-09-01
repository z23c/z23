/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:frontier-gate-primitives — these are the shared gate
// primitives (frontier read, candidate clamp, evidence-based floor rewind)
// consumed by the zcl_result-returning commit/restore surfaces in
// utxo_recovery_service.c / utxo_recovery_restore.c. Every refusal travels
// via structured LOG_WARN + EV_RECOVERY_ACTION, and the callers wrap the
// verdict in their own zcl_result.
/*
 * INVARIANT A — never INSTALL a tip above what can be DERIVED.
 *
 * Failure mode this guards: a boot restore can install a tip from a
 * finalized-floor row whose own hash resolves to a DIFFERENT height on a
 * detached index island above the trust root, producing tip-window holes
 * plus active-chain mismatches and a crash loop.
 *
 * The LOG half alone is fabricatable: a fabricated anchor row plus
 * advanced stage cursors makes reducer_trusted_anchor accept an
 * underivable frontier above the floor. Both authorities must agree
 * before an install:
 *
 *   LOG half   — utxo_recovery_header_frontier: the contiguous ok=1
 *       prefix of validate_headers_log (DRY reader
 *       reducer_frontier_log_frontier). No log evidence => fail open.
 *   INDEX half — utxo_recovery_block_trust_rooted: the candidate must be
 *       hash-linked (contiguous pprev) down to a trust root the node can
 *       actually serve from: genesis, or the compiled SHA3 UTXO anchor.
 *       A detached island above the anchor is not derivable state no
 *       matter what the logs claim.
 *
 * This file is the gate, not a repair ladder:
 *
 *   utxo_recovery_clamp_tip_to_header_frontier — committed tip =
 *       min(candidate, frontier), resolved hash-linked (pprev descent,
 *       falling back to the log's OWN recorded hash when the extent is
 *       torn) — never a height-only lookup — and refused outright when
 *       the resolved block is not trust-rooted.
 *   utxo_recovery_rewind_finalized_floor — a finalized floor that
 *       neither authority can back is provably unbackable; flip its
 *       ok=1 rows to ok=0 (history preserved, status marks provenance).
 *       Loud.
 *
 * Bodies may legitimately lag the header frontier — the post-restore
 * integrity check counts block-index holes, not missing bodies, so
 * clamping to the validate_headers frontier is sufficient; body_fetch
 * refills. Kept as a dedicated seam file so utxo_recovery_restore.c stays
 * under the app/ file-size ceiling (E1).
 */

#include "services/utxo_recovery_service.h"
#include "services/block_index_loader.h"
#include "chain/chain.h"                 /* block_index_build_skip */
#include "validation/main_state.h"
#include "jobs/reducer_frontier.h"
#include "chain/checkpoints.h"
#include "storage/progress_store.h"
#include "event/event.h"

#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"             /* zcl_malloc for the pass-2 journal */

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utxo_recovery_internal.h"

int utxo_recovery_finalized_served_floor(struct uint256 *hash_out,
                                         bool *have_hash_out)
{
    if (hash_out)
        memset(hash_out, 0, sizeof(*hash_out));
    if (have_hash_out)
        *have_hash_out = false;

    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        LOG_RETURN(-1, "utxo_recovery",
                   "served_floor read skipped: progress_store not open");

    sqlite3_stmt *st = NULL;
    int floor = -1;
    progress_store_tx_lock();
    if (sqlite3_prepare_v2(
            pdb,
            "SELECT height, tip_hash FROM tip_finalize_log "
            "WHERE ok=1 ORDER BY height DESC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        LOG_RETURN(-1, "utxo_recovery",
                   "served_floor read prepare failed: %s",
                   sqlite3_errmsg(pdb));
    }
    if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
        floor = sqlite3_column_int(st, 0);
        const void *blob = sqlite3_column_blob(st, 1);
        int blob_len = sqlite3_column_bytes(st, 1);
        if (hash_out && have_hash_out && blob && blob_len == 32) {
            memcpy(hash_out->data, blob, 32);
            *have_hash_out = true;
        }
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return floor;
}

bool utxo_recovery_header_frontier(int32_t *out_h)
{
    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        return false;
    return reducer_frontier_log_frontier(pdb, "validate_headers_log",
                                         "validate_headers", out_h);
}

/* PART C — provenance-matched cold-import seed-anchor trust root. The operator
 * cold-imported a SHA3-attested UTXO snapshot whose base sits ABOVE the
 * compiled SHA3 anchor; that base is a legitimate trust-root terminus, but
 * ancestry_break only knows the compiled anchor. Cache the (hash,height) so
 * the walk can terminate cleanly there. Set once at boot before background
 * consumers run; read lock-free below (a benign stale read can only WITHHOLD
 * the relaxation, never grant it to a wrong block — the hash must match). */
static struct uint256 g_cold_import_anchor_hash;
static int32_t        g_cold_import_anchor_h = -1;
static bool           g_cold_import_anchor_set = false;

void utxo_recovery_set_cold_import_trust_anchor(const struct uint256 *hash,
                                                int32_t height)
{
    if (hash && height > 0) {
        g_cold_import_anchor_hash = *hash;
        g_cold_import_anchor_h    = height;
        g_cold_import_anchor_set  = true;
    } else {
        g_cold_import_anchor_set  = false;
        g_cold_import_anchor_h    = -1;
    }
}

/* True iff p IS the provenance-matched cold-import trust anchor — the
 * operator's cold-import UTXO-snapshot base or the cured coins tip a
 * shielded-history import registers: a SHA3-attested trust-root terminus
 * ABOVE the compiled SHA3 anchor. Requires an EXACT (height, hash) match, so a
 * non-matching torn/orphan root is never granted the relaxation (the
 * detached-island guard stays intact for every value except this one). */
static bool utxo_recovery_cold_import_anchor_matches(const struct block_index *p)
{
    return g_cold_import_anchor_set && p && p->phashBlock &&
           p->nHeight == g_cold_import_anchor_h &&
           uint256_cmp(p->phashBlock, &g_cold_import_anchor_hash) == 0;
}

const struct block_index *utxo_recovery_block_ancestry_break(
    const struct block_index *bi)
{
    if (!bi)
        return NULL;

    /* The candidate ITSELF may be the registered cold-import trust anchor: the
     * shielded-history import attests the cured coins tip (exact height+hash) as
     * an SHA3-provenance terminus. A height tear BELOW it (between the compiled
     * anchor and the cured tip) must NOT refuse it — the attestation is the
     * proof. Check the candidate up front, mirroring the tear-point and
     * pprev-less-root cold-import checks below; a non-matching candidate still
     * descends and is refused if it is a genuine detached island. */
    if (utxo_recovery_cold_import_anchor_matches(bi))
        return NULL;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    const int32_t anchor = cp ? cp->height
                              : REDUCER_FRONTIER_TRUSTED_ANCHOR;

    /* Contiguous pprev descent: every hop must decrement the height by
     * exactly 1, so the walk terminates in at most bi->nHeight steps and
     * a height tear (the detached-island shape) is detected immediately.
     * Early-exit once the walk crosses the compiled SHA3 anchor — the
     * extent below it is attested by the checkpoint, so contiguity above
     * the anchor is the whole proof (caps the walk at ~tip-anchor hops). */
    const struct block_index *p = bi;
    while (p->pprev) {
        if (p->pprev->nHeight != p->nHeight - 1) {
            /* Height tear — p is the island root, UNLESS p is itself the
             * provenance-matched cold-import trust anchor. A shielded-history
             * import registers the cured coins tip (a legitimate SHA3-attested
             * terminus above the compiled anchor) whose block-index ancestry
             * is torn just below it; terminating here — on an EXACT (height,
             * hash) match only — lets Invariant A install that tip instead of
             * refusing it as a detached island. Every other torn root still
             * returns p and is refused. */
            if (utxo_recovery_cold_import_anchor_matches(p))
                return NULL;
            return p;          /* height tear — p is the island root */
        }
        p = p->pprev;
        if (p->nHeight <= anchor)
            return NULL;       /* crossed the attested anchor extent */
    }
    /* Root reached: genesis, or an extent rooted at/just above the
     * compiled anchor (snapshot-anchored nodes and the test segments
     * root exactly there). A root strictly above anchor+1 is a detached
     * island — not derivable state. */
    if (p->nHeight == 0 || p->nHeight <= anchor + 1)
        return NULL;
    /* PART C: the operator's cold-import UTXO-snapshot seed anchor is a
     * SHA3-attested trust root above the compiled anchor — terminate cleanly
     * at it ONLY when the reached root provenance-matches (exact hash+height).
     * A non-matching detached island still returns p and is refused, so the
     * detached-island guard is intact for every torn/orphan-seeded root. */
    if (utxo_recovery_cold_import_anchor_matches(p))
        return NULL;
    return p;
}

bool utxo_recovery_block_trust_rooted(const struct block_index *bi)
{
    if (!bi || bi->nHeight < 0)
        return false;
    return utxo_recovery_block_ancestry_break(bi) == NULL;
}

/* ── Scoped ancestry-height relink (LDB-import header-only tear) ─────────
 * See services/utxo_recovery_service.h for the full contract + the failure
 * class this cures (a hash-linked but height-scrambled header-only ancestor
 * neither boot repair pass can reach). */
struct utxo_recovery_ancestry_repair
utxo_recovery_relink_scrambled_ancestry(struct main_state *ms,
                                        struct block_index *tip)
{
    struct utxo_recovery_ancestry_repair r = {
        .result = UTXO_ANCESTRY_REPAIR_NOOP,
        .fixed = 0, .island_root_h = -1, .refuse_at_h = -1,
    };
    if (!ms || !tip || tip->nHeight < 0)
        return r;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    const int32_t anchor = cp ? cp->height
                              : REDUCER_FRONTIER_TRUSTED_ANCHOR;

    /* Already trust-rooted (or entirely inside the attested extent): nothing
     * to do. The island root also gives the loud-log context. */
    const struct block_index *island =
        utxo_recovery_block_ancestry_break(tip);
    if (!island || tip->nHeight <= anchor + 1)
        return r;                              /* NOOP */
    r.island_root_h = island->nHeight;

    /* PASS 1 — VALIDATE (no mutation). Walk tip -> anchor via pprev (the store's
     * OWN in-memory hash linkage), tracking the authoritative height from the
     * trusted coins tip. This only ever CURES a pure label scramble on an
     * otherwise-intact, acyclic, correct-lineage chain. It FAILS CLOSED (mutating
     * nothing) on the three shapes a height relabel provably cannot cure:
     *
     *   1. A NULL / foreign / self-inconsistent parent above the anchor — a
     *      genuine missing-parent break, not a label scramble.
     *   2. A pprev CYCLE ("lasso"): the block-index loader's by-height pprev
     *      fallback (block_index_loader.c) can wire a WRONG parent from a
     *      scrambled stored height, so the walk laps a cycle forever. A height
     *      relabel cannot cure wrong pprev linkage, and mutating a cycle stamps
     *      garbage — Floyd tortoise/hare detects it (the max_steps backstop is
     *      NOT enough: correct_h decrements every step so it cannot fire on a
     *      lasso whose height-labels lie).
     *   3. A terminus whose hash is NOT the compiled checkpoint block — a
     *      wrong-lineage acyclic path would otherwise get the anchor height
     *      stamped onto a non-checkpoint block, pass a height-only post-check,
     *      and fail-open trust-root O(tip-anchor) mislabels. */
    int64_t max_steps = (int64_t)tip->nHeight - (int64_t)anchor + 8;
    int64_t steps = 0;
    int fixes_needed = 0;
    int32_t correct_h = tip->nHeight;
    struct block_index *cur = tip;
    struct block_index *hare = tip;           /* Floyd cycle guard */
    struct block_index *terminus = NULL;
    bool repairable = false, cycle = false;
    for (;;) {
        int32_t parent_h = correct_h - 1;
        /* Descend DOWN TO AND INCLUDING the node at the anchor height: ancestry_
         * break only trust-roots once its contiguous descent reaches a node whose
         * stored nHeight <= anchor, so the anchor node's own label must read
         * exactly `anchor`. Below the anchor is the attested extent. */
        if (parent_h < anchor) {              /* cur is the anchor-height node */
            terminus = cur;
            repairable = true;
            break;
        }
        struct block_index *pp = cur->pprev;
        if (!pp || !pp->phashBlock ||
            block_map_find(&ms->map_block_index, pp->phashBlock) != pp) {
            r.refuse_at_h = correct_h;        /* missing-parent linkage break */
            break;
        }
        if (pp->nHeight != parent_h)
            fixes_needed++;
        cur = pp;
        correct_h = parent_h;
        /* Floyd cycle detection over the pprev POINTERS (never heights, which
         * lie): hare advances two, tortoise (cur) one; a meet is a lasso. */
        if (hare) hare = hare->pprev;
        if (hare) hare = hare->pprev;
        if (hare && hare == cur) { cycle = true; r.refuse_at_h = correct_h; break; }
        if (++steps > max_steps) {            /* defensive backstop */
            r.refuse_at_h = correct_h;
            break;
        }
    }

    /* Terminus IDENTITY: the node the walk reaches at the anchor height MUST be
     * the compiled checkpoint block, or the whole lineage is wrong. */
    if (repairable && cp && terminus) {
        struct uint256 cph;
        memcpy(cph.data, cp->block_hash, 32);
        if (!terminus->phashBlock ||
            uint256_cmp(terminus->phashBlock, &cph) != 0) {
            repairable = false;
            r.refuse_at_h = terminus->nHeight;
        }
    }

    if (!repairable) {
        /* FAIL-CLOSED: a pprev lasso, a genuine missing-parent break, or a
         * wrong-lineage terminus — real corruption a label relabel cannot cure.
         * Name a typed blocker; MUTATE NOTHING. */
        const char *why = cycle ? "pprev cycle (loader by-height fallback wired a "
                                  "wrong parent from a scrambled height)"
                                : "pprev torn / wrong-lineage above the attested extent";
        struct blocker_record br;
        if (blocker_init(&br, UTXO_RECOVERY_ANCESTRY_TEAR_BLOCKER_ID,
                         "utxo_recovery", BLOCKER_DEPENDENCY, NULL)) {
            br.retry_budget = -1;              /* unbounded — wait for backfill */
            snprintf(br.reason, sizeof(br.reason),
                     "coins_tip=%d refuse_at=%d anchor=%d island_root=%d cycle=%d "
                     "(%s)",
                     tip->nHeight, r.refuse_at_h, anchor, r.island_root_h,
                     cycle ? 1 : 0, why);
            (void)blocker_set(&br);            /* rate-limited dup is fine */
        }
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=ancestry_relink_refused coins_tip=%d refuse_at=%d "
                    "anchor=%d island_root=%d cycle=%d",
                    tip->nHeight, r.refuse_at_h, anchor, r.island_root_h,
                    cycle ? 1 : 0);
        LOG_WARN("utxo_recovery",
                 "SCOPED ANCESTRY RELINK REFUSED: coins tip h=%d is a detached "
                 "island (refuse_at=%d anchor=%d island_root=%d cycle=%d) — %s; "
                 "changed nothing (a height relabel cannot cure wrong pprev "
                 "linkage), waiting on backfill / loader repair",
                 tip->nHeight, r.refuse_at_h, anchor, r.island_root_h,
                 cycle ? 1 : 0, why);
        r.result = UTXO_ANCESTRY_REPAIR_REFUSED;
        return r;
    }

    if (fixes_needed == 0) {
        /* Repairable path is fully contiguous already — nothing to relabel. */
        r.result = UTXO_ANCESTRY_REPAIR_NOOP;
        return r;
    }

    /* PASS 2 — APPLY, JOURNALED. The boot shutdown persists the flat block index
     * UNCONDITIONALLY (boot_services_shutdown), so a mutation that does not end
     * up trust-rooting the tip must NOT survive this call — journal (node,
     * old_height) and revert on any post-check failure. */
    struct relink_jrnl { struct block_index *node; int32_t old_h; };
    struct relink_jrnl *jrnl =
        zcl_malloc((size_t)fixes_needed * sizeof(*jrnl), "relink_journal");
    if (!jrnl) {
        LOG_WARN("utxo_recovery",
                 "SCOPED ANCESTRY RELINK: journal alloc failed for %d node(s) — "
                 "refusing WITHOUT mutation (fail-closed, non-corrupting)",
                 fixes_needed);
        r.result = UTXO_ANCESTRY_REPAIR_REFUSED;
        return r;
    }
    size_t jn = 0;
    correct_h = tip->nHeight;
    cur = tip;
    for (;;) {
        int32_t parent_h = correct_h - 1;
        if (parent_h < anchor)                 /* through the anchor node (pass 1) */
            break;
        struct block_index *pp = cur->pprev;   /* proven non-NULL in pass 1 */
        if (pp->nHeight != parent_h) {
            if (jn < (size_t)fixes_needed) {
                jrnl[jn].node = pp;
                jrnl[jn].old_h = pp->nHeight;
                jn++;
            }
            pp->nHeight = parent_h;
            r.fixed++;
        }
        cur = pp;
        correct_h = parent_h;
    }

    /* Authoritative verdict: the tip must now be trust-rooted. If not (defensive
     * — pass 1 proved the path acyclic with a checkpoint terminus), REVERT every
     * mutation so the shutdown save cannot persist unverified labels. */
    if (utxo_recovery_block_ancestry_break(tip) != NULL) {
        for (size_t i = jn; i > 0; i--)
            jrnl[i - 1].node->nHeight = jrnl[i - 1].old_h;
        free(jrnl);
        LOG_WARN("utxo_recovery",
                 "SCOPED ANCESTRY RELINK: relabeled %d then REVERTED (post-check "
                 "still a detached island) — coins tip h=%d unchanged",
                 r.fixed, tip->nHeight);
        r.fixed = 0;
        r.result = UTXO_ANCESTRY_REPAIR_REFUSED;
        return r;
    }

    /* SUCCESS. The labels changed, so pskip (built FROM nHeight in chain.c, NOT
     * height-independent) is now stale for every mutated node — rebuild it
     * lowest-first (parents before children) so block_index_get_ancestor stays
     * correct for same-boot consumers (tip publish / successor / watchdog). */
    for (size_t i = jn; i > 0; i--)
        block_index_build_skip(jrnl[i - 1].node);
    free(jrnl);

    LOG_WARN("utxo_recovery",
             "SCOPED ANCESTRY RELINK: coins tip h=%d had a height-label scramble "
             "in its ancestry (island_root=%d anchor=%d); relabeled + skip-rebuilt "
             "%d node(s) on an acyclic checkpoint-terminated chain — tip is now "
             "trust-rooted", tip->nHeight, r.island_root_h, anchor, r.fixed);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=ancestry_relink_fixed coins_tip=%d island_root=%d "
                "anchor=%d fixed=%d",
                tip->nHeight, r.island_root_h, anchor, r.fixed);
    r.result = UTXO_ANCESTRY_REPAIR_FIXED;
    return r;
}

void utxo_recovery_relink_island_if_present(struct utxo_recovery_ctx *ctx,
                                            struct block_index *tip)
{
    if (!ctx || !ctx->state || !tip)
        return;
    /* Gate on an island actually being present so a healthy datadir pays one
     * bounded pprev walk and nothing else. */
    if (utxo_recovery_block_ancestry_break(tip) == NULL)
        return;
    struct utxo_recovery_ancestry_repair rep =
        utxo_recovery_relink_scrambled_ancestry(ctx->state, tip);
    if (rep.result == UTXO_ANCESTRY_REPAIR_FIXED &&
        ctx->state->map_block_index.size > 1000)
        /* Persist the corrected labels so the next boot loads them (and
         * re-derives skip links from the correct heights) — the same durable
         * flat save the boot repair passes use. Best-effort: even without it the
         * relink re-fires on the next boot; REFUSED already set its typed
         * blocker inside the relink. */
        save_block_index_flat(ctx->datadir, ctx->state);
}

/* Shared band-fact recorder: blocker (the loud cache) + event + WARN.
 * No escape action — the periodic getheaders planner is the driver
 * (syncsvc_header_band_backfill_anchor keys off blocker existence). */
static void utxo_recovery_record_band(const char *producer,
                                      int32_t installed_h,
                                      int32_t island_root_h,
                                      int32_t frontier_h)
{
    if (!producer)
        producer = "unknown";
    struct blocker_record br;
    if (!blocker_init(&br, HEADER_BAND_BLOCKER_ID, "utxo_recovery",
                      BLOCKER_DEPENDENCY, NULL))
        return;            /* blocker_init logged the reason */
    snprintf(br.reason, sizeof(br.reason),
             "producer=%s installed=%d island_root=%d frontier=%d",
             producer, installed_h, island_root_h, frontier_h);
    (void)blocker_set(&br);  /* rate-limited dup is fine — fact persists */
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=header_band_detected producer=%s installed=%d "
                "island_root=%d frontier=%d",
                producer, installed_h, island_root_h, frontier_h);
    LOG_WARN("utxo_recovery",
             "HEADER BAND HOLE recorded: %s installed h=%d above the "
             "trust-rooted header frontier (island_root=%d frontier=%d) — "
             "headers below the island will be backfilled from the "
             "frontier (record-only; install proceeds)",
             producer, installed_h, island_root_h, frontier_h);
}

void utxo_recovery_note_band_unrooted_tip(const struct block_index *tip,
                                          const char *producer)
{
    /* The band fact is derived from INDEX ancestry (pprev contiguity to
     * a trust root), never from the reducer log frontier. The log half
     * does NOT abstain on an empty progress db — log_contiguous_prefix
     * collapses to the compiled SHA3 anchor — so a log-frontier-derived
     * producer cried wolf on every clean two-step cold-import
     * (--importblockindex then a normal boot): a fully contiguous
     * imported header chain was recorded as a band hole and the first
     * accepted batch fired a false closure. Ancestry derivation is
     * correct on both paths: a pprev-less installed anchor above the
     * compiled anchor IS the island root; a contiguous chain walks to
     * its trust root and abstains. */
    if (!tip)
        return;
    const struct block_index *root = utxo_recovery_block_ancestry_break(tip);
    if (!root)
        return;            /* trust-rooted — no band */
    int32_t fh = -1;
    (void)utxo_recovery_header_frontier(&fh);  /* context only; -1 = log abstains */
    utxo_recovery_record_band(producer, tip->nHeight, root->nHeight, fh);
}

struct block_index *utxo_recovery_clamp_tip_to_header_frontier(
    struct utxo_recovery_ctx *ctx, struct block_index *candidate,
    const char *reason, int32_t *frontier_out, bool *clamped_out)
{
    if (clamped_out)
        *clamped_out = false;
    if (frontier_out)
        *frontier_out = -1;
    if (!ctx || !ctx->state || !candidate)
        return candidate;
    if (!reason)
        reason = "utxo_recovery";

    int32_t fh = 0;
    if (!utxo_recovery_header_frontier(&fh))
        return candidate;              /* fail-open: behave as today */
    if (frontier_out)
        *frontier_out = fh;
    if (candidate->nHeight <= fh) {
        /* Log-derivable — but the INDEX must agree: the log frontier can
         * be fabricated ABOVE the candidate, so a height test alone would
         * install a detached-island tip. */
        if (utxo_recovery_block_trust_rooted(candidate))
            return candidate;          /* derivable by BOTH authorities */
        LOG_WARN("utxo_recovery",
                 "Invariant A clamp: candidate h=%d is within the validated "
                 "header frontier h=%d but is NOT hash-linked to a trust "
                 "root (genesis / SHA3 anchor) — detached island; refusing "
                 "install (reason=%s)", candidate->nHeight, fh, reason);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=restore_tip_refused candidate=%d frontier=%d "
                    "via=unrooted reason=%s", candidate->nHeight, fh, reason);
        return NULL;
    }

    /* LOG-UNKNOWN carve-out: the stage logs are rolling windows. A
     * candidate BELOW the oldest row the log still covers cannot be
     * refuted by the log — only fail to be vouched for — so the log half
     * abstains and the index half (trust-rooted ancestry) decides alone.
     * Without this carve-out, rewinding fabricated anchor rows collapses
     * the frontier to the compiled SHA3 anchor and drags a trust-rooted
     * candidate tens of thousands of blocks down to it. */
    {
        int32_t log_lo = 0;
        bool lo_found = false;
        if (reducer_frontier_log_coverage_floor(progress_store_db(),
                "validate_headers_log", &log_lo, &lo_found) &&
            lo_found && candidate->nHeight < log_lo) {
            if (utxo_recovery_block_trust_rooted(candidate)) {
                LOG_INFO("utxo_recovery",
                         "Invariant A clamp: candidate h=%d is below the "
                         "validate_headers_log coverage window (oldest row "
                         "h=%d, frontier h=%d) — log abstains; committing "
                         "on trust-rooted index ancestry (reason=%s)",
                         candidate->nHeight, log_lo, fh, reason);
                return candidate;
            }
            LOG_WARN("utxo_recovery",
                     "Invariant A clamp: candidate h=%d is below the log "
                     "coverage window (oldest row h=%d) AND not trust-rooted; "
                     "refusing install (reason=%s)",
                     candidate->nHeight, log_lo, reason);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=restore_tip_refused candidate=%d frontier=%d "
                        "via=unrooted_below_log_window reason=%s",
                        candidate->nHeight, fh, reason);
            return NULL;
        }
    }

    /* 1) hash-linked descent: pprev only, never by-height. Bounded by the
     * height gap and requiring strictly-descending heights so a corrupt
     * block-index cycle cannot spin boot before it reaches the log-hash
     * fallback/refusal below. */
    struct block_index *walk = candidate;
    int64_t max_hops = (int64_t)candidate->nHeight - (int64_t)fh + 1;
    int64_t hops = 0;
    while (walk && walk->nHeight > fh) {
        struct block_index *prev = walk->pprev;
        if (!prev) {
            walk = NULL;
            break;
        }
        if (prev->nHeight >= walk->nHeight || ++hops > max_hops) {
            LOG_WARN("utxo_recovery",
                     "Invariant A clamp: non-descending/cyclic pprev while "
                     "walking restore candidate h=%d toward frontier h=%d "
                     "(at h=%d prev_h=%d hops=%lld max=%lld reason=%s)",
                     candidate->nHeight, fh, walk->nHeight, prev->nHeight,
                     (long long)hops, (long long)max_hops, reason);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=restore_tip_pprev_cycle candidate=%d "
                        "frontier=%d at=%d prev=%d reason=%s",
                        candidate->nHeight, fh, walk->nHeight,
                        prev->nHeight, reason);
            walk = NULL;
            break;
        }
        walk = prev;
    }
    if (walk && walk->nHeight == fh &&
        utxo_recovery_block_trust_rooted(walk)) {
        if (clamped_out)
            *clamped_out = true;
        LOG_WARN("utxo_recovery",
                 "Invariant A clamp: restore candidate h=%d above validated "
                 "header frontier h=%d; committing hash-linked ancestor "
                 "(reason=%s)", candidate->nHeight, fh, reason);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=restore_tip_clamp candidate=%d frontier=%d "
                    "via=pprev reason=%s", candidate->nHeight, fh, reason);
        return walk;
    }

    /* 2) torn extent (pprev dies above fh or cycles/non-descends before fh):
     * derive the frontier tip from validate_headers_log's OWN hash
     * (log-as-truth). */
    uint8_t lh[32];
    bool found = false;
    if (reducer_frontier_log_hash_at(progress_store_db(),
            "validate_headers_log", "hash", fh, lh, &found) && found) {
        struct uint256 fhash;
        memcpy(fhash.data, lh, 32);
        struct block_index *fb =
            block_map_find(&ctx->state->map_block_index, &fhash);
        if (fb && fb->nHeight == fh &&
            utxo_recovery_block_trust_rooted(fb)) {
            if (clamped_out)
                *clamped_out = true;
            LOG_WARN("utxo_recovery",
                     "Invariant A clamp: restore candidate h=%d above "
                     "validated header frontier h=%d and pprev chain is "
                     "torn; committing the frontier block from "
                     "validate_headers_log's own hash (reason=%s)",
                     candidate->nHeight, fh, reason);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=restore_tip_clamp candidate=%d frontier=%d "
                        "via=log_hash reason=%s",
                        candidate->nHeight, fh, reason);
            return fb;
        }
    }

    LOG_WARN("utxo_recovery",
             "Invariant A clamp: candidate h=%d not hash-linked to frontier "
             "h=%d via a trust-rooted chain and the frontier block does not "
             "resolve; refusing install (reason=%s)",
             candidate->nHeight, fh, reason);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=restore_tip_refused candidate=%d frontier=%d "
                "reason=%s", candidate->nHeight, fh, reason);
    return NULL;
}

int utxo_recovery_settle_finalized_floor(struct utxo_recovery_ctx *ctx,
                                         int scan_fallback_h,
                                         int served_floor,
                                         struct uint256 *served_hash,
                                         bool *have_served_hash)
{
    /* Only a floor BOTH Invariant A authorities can BACK is real:
     *
     *   LOG half   — the floor sits within the validated header frontier
     *                (abstains fail-open with no log evidence, or when
     *                the floor predates the log's rolling window);
     *   INDEX half — the floor row's OWN hash resolves in the index AT
     *                the recorded height, on a trust-rooted chain.
     *
     * A fabricated floor can fail the index half: its row hash maps to a
     * DIFFERENT height on a detached island while fabricated anchor rows
     * push the LOG frontier above it so a log-only test passes. Flip
     * unbackable rows (loudest-first, history preserved) until the floor
     * is evidence again or stops outranking scan_fallback. */
    if (!ctx || !ctx->state || !served_hash || !have_served_hash)
        return served_floor;

    int32_t fh = -1;
    bool have_fh = utxo_recovery_header_frontier(&fh);
    int32_t log_lo = 0;
    bool have_log_lo = false;
    {
        bool lo_found = false;
        if (reducer_frontier_log_coverage_floor(progress_store_db(),
                "validate_headers_log", &log_lo, &lo_found) && lo_found)
            have_log_lo = true;
    }
    int flipped_passes = 0;
    while (served_floor > scan_fallback_h) {
        struct block_index *fb = *have_served_hash
            ? block_map_find(&ctx->state->map_block_index, served_hash)
            : NULL;
        bool log_backed = !have_fh || served_floor <= fh ||
            (have_log_lo && served_floor < log_lo);
        bool index_backed = fb && fb->nHeight == served_floor &&
            utxo_recovery_block_trust_rooted(fb);
        if (log_backed && index_backed)
            break;  /* real authority — hold the floor */

        /* A floor above the log frontier rewinds to the frontier in one
         * pass; an index-unbackable row flips alone so any backable row
         * beneath it survives. */
        int32_t bound = (!log_backed && fh < served_floor)
            ? fh : served_floor - 1;
        if (!utxo_recovery_rewind_finalized_floor(
                bound, served_floor, "scan_fallback_guard"))
            break;  /* write failure: hold (fail closed) */
        flipped_passes++;
        int prev_floor = served_floor;
        served_floor = utxo_recovery_finalized_served_floor(
            served_hash, have_served_hash);
        if (served_floor >= prev_floor) {
            LOG_WARN("utxo_recovery",
                     "floor rewind made no progress (h=%d); holding floor",
                     served_floor);
            break;  /* defensive: never spin */
        }
    }
    if (flipped_passes > 0)
        LOG_WARN("utxo_recovery",
                 "finalized-floor rewind settled after %d pass(es): floor "
                 "now h=%d (scan_fallback h=%d, header frontier h=%d)",
                 flipped_passes, served_floor, scan_fallback_h,
                 have_fh ? fh : -1);
    return served_floor;
}

bool utxo_recovery_rewind_finalized_floor(int32_t frontier, int floor,
                                          const char *reason)
{
    if (floor <= frontier)
        return true;       /* floor is backable: anti-rewind holds */
    if (!reason)
        reason = "utxo_recovery";
    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        LOG_RETURN(false, "utxo_recovery",
                   "floor rewind skipped: progress_store not open");

    progress_store_tx_lock();
    /* Ensure the itag column exists so the SET itag=NULL below prepares even on
     * a datadir whose tip_finalize_log predates the integrity-tag migration
     * (SQLite validates columns at prepare time regardless of matched rows).
     * Idempotent: a duplicate-column error is the expected already-migrated
     * case. */
    {
        char *aerr = NULL;
        (void)sqlite3_exec(pdb,
            "ALTER TABLE tip_finalize_log ADD COLUMN itag BLOB",
            NULL, NULL, &aerr);
        if (aerr) sqlite3_free(aerr);
    }
    sqlite3_stmt *st = NULL;
    /* Clear itag on the rewound rows: their (height, ok) verdict just changed,
     * so the old tag would spuriously MISMATCH in the reducer fold. A NULL tag
     * is treated as untagged (trust ok), and ok is now 0 — the fold caps H* at
     * `frontier` with no false integrity alarm. Re-finalization re-tags them.
     * See stage_row_itag.h. */
    bool ok = sqlite3_prepare_v2(pdb,
        "UPDATE tip_finalize_log SET ok=0, status='floor_rewind', itag=NULL "
        "WHERE ok=1 AND height > ?", -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int(st, 1, frontier);
        ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:progress-kv-kernel-store
    }
    int rows = ok ? sqlite3_changes(pdb) : 0;
    if (st)
        sqlite3_finalize(st);
    progress_store_tx_unlock();
    if (!ok)
        LOG_RETURN(false, "utxo_recovery", "floor rewind UPDATE failed: %s",
                   sqlite3_errmsg(pdb));

    LOG_WARN("utxo_recovery",
             "FINALIZED FLOOR REWIND: floor h=%d is above the highest "
             "servable height h=%d (unbackable evidence); rewound %d ok=1 "
             "rows reason=%s", floor, frontier, rows, reason);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=finalized_floor_rewind floor=%d frontier=%d rows=%d "
                "reason=%s", floor, frontier, rows, reason);
    return ok;
}
