/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Resume-candidate selection and fail-closed accounting for the Sapling
 * tree rebuild.
 *
 * sync_controller_sapling_tree.c owns the replay LOOP. This file owns the
 * three decisions that loop delegates:
 *   - where the replay may start (the anchor_kv frontier candidate),
 *   - what a block the replay could not fold costs (skip accounting),
 *   - how a fail-closed outcome is classified for operators.
 * Declarations live in sync_controller_internal.h. */

#include "sync_controller_internal.h"

#include "base/text_fit.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

bool sapling_rebuild_header_root_known(const struct block_index *bi)
{
    static const uint8_t zeros32[32] = {0};

    return bi && memcmp(bi->hashFinalSaplingRoot.data, zeros32, 32) != 0;
}

/* Pre-flight: prove from HEADERS ALONE that the replay about to run cannot
 * reproduce a header-committed root, before walking a single block.
 *
 * The shape this exists for is a snapshot-seeded datadir. Bodies below the seed
 * height were never downloaded, so `start_height` opens onto a run of heights
 * whose block index carries no BLOCK_HAVE_DATA. The replay loop tolerates each
 * of those as a skip (header-tip endpoint), folds nothing, and then reports the
 * first Sapling-commitment block ABOVE the body floor as a root mismatch — a
 * downstream shadow. On the live node that read
 * `height=3155873 commitments=1 mismatches=1`: a one-leaf tree measured against
 * a root committing ~1.79M leaves, at a height 30 blocks above the real
 * boundary, after 2.68M tolerated skips and thousands of log lines.
 *
 * The proof needs no bodies. Let F be the first height at/above `start_height`
 * whose body is foldable, and B = F-1 the last height in the absent run. The
 * frontier the loop must hold when it reaches F is exactly the tree after block
 * B, and the header chain COMMITS that tree's root in hashFinalSaplingRoot(B).
 * Appends only ever add leaves, and the loop folds nothing over [start_height,
 * B], so the tree it carries into F is the tree it started with. If that
 * starting tree's root already differs from hashFinalSaplingRoot(B), every
 * subsequent per-block root check is doomed: the commitments that would close
 * the gap live in bodies that are not on disk.
 *
 * Conservative by construction — false only, never wrongly true:
 *   - F == start_height (no absent run) => not our call.
 *   - no foldable body anywhere in range => B = chain_tip, same test against
 *     the endpoint's own committed root.
 *   - hashFinalSaplingRoot(B) unknown (pre-activation/header-only) => cannot
 *     prove, fall through to the walk unchanged.
 *   - roots EQUAL => the absent run carried no commitments; the walk is
 *     legitimately recoverable and runs unchanged.
 *
 * Detection and reporting only: no consensus predicate, no fold result, and no
 * acceptance decision changes — a walk that could have succeeded still runs.
 * The absent run's per-class counts come back split so the caller reports it
 * with the same typed classes the loop's own skip tally uses; the WARN that
 * names the boundary is emitted here so the call site stays a guard. */
bool sapling_rebuild_replay_is_impossible(
        const struct active_chain *chain,
        const struct incremental_merkle_tree *start_tree,
        int start_height, int chain_tip,
        struct sapling_rebuild_impossible *out)
{
    if (!chain || !start_tree || !out || start_height > chain_tip)
        return false;

    int first_body_h = -1;
    int no_index = 0;
    int no_data = 0;
    for (int h = start_height; h <= chain_tip; h++) {
        const struct block_index *bi = active_chain_at(chain, h);
        if (!bi) {
            no_index++;
            continue;
        }
        if (!(bi->nStatus & BLOCK_HAVE_DATA)) {
            no_data++;
            continue;
        }
        first_body_h = h;
        break;
    }

    int gap_last_h = (first_body_h >= 0) ? first_body_h - 1 : chain_tip;
    if (gap_last_h < start_height)
        return false;   // raw-return-ok:the first height is foldable — no absent run, the walk runs unchanged

    const struct block_index *bi_b = active_chain_at(chain, gap_last_h);
    if (!sapling_rebuild_header_root_known(bi_b))
        return false;   // raw-return-ok:no committed root at the boundary — nothing to prove against, the walk runs unchanged

    struct uint256 start_root;
    incremental_tree_root(start_tree, &start_root);
    if (memcmp(start_root.data, bi_b->hashFinalSaplingRoot.data, 32) == 0)
        return false;   // raw-return-ok:the absent run carried no commitments — the walk is recoverable and runs unchanged

    out->first_body_h = first_body_h;
    out->gap_last_h = gap_last_h;
    out->no_index = no_index;
    out->no_data = no_data;
    LOG_WARN("sapling_tree_rebuild",
             "sapling_tree_rebuild: refusing the replay h=%d..%d before "
             "reading a block — no body is foldable below h=%d and the header "
             "chain commits a different Sapling root at h=%d than the frontier "
             "this walk would start from, so the commitments that would close "
             "the gap are not on disk (absent run [%d..%d] no_index=%d "
             "no_data=%d)",
             start_height, chain_tip, first_body_h, gap_last_h, start_height,
             gap_last_h, no_index, no_data);
    return true;
}

/* Raise (or clear) the fail-closed blocker family the boot-time "Sapling
 * tree root MISMATCH" path drives sapling_tree_rebuild() through — every
 * fail-closed reason from this function (root mismatch included) shares
 * one blocker id so operators see a single named signal instead of raw
 * log lines.
 *
 * Classification of a root mismatch depends on whether the walk could even
 * have produced the header root:
 *   - skips TOLERATED below the mismatch height ⇒ commitments are
 *     KNOWN-MISSING (their bodies are not on disk), so the rebuilt tree
 *     could not match no matter how healthy the derived state is. That is a
 *     body-availability DEPENDENCY — the cure is the anchor_kv frontier
 *     seed above or a body backfill, never operator corruption triage.
 *     This is the structural shape of a cure-seeded datadir, where bodies
 *     exist only above the cure anchor.
 *   - ZERO tolerated skips ⇒ the walk folded every in-range body and STILL
 *     disagreed with the header-committed root: a genuine derived-state
 *     disagreement, PERMANENT (unchanged).
 * Every other reason (serialize/persist plumbing) stays TRANSIENT. */
void sapling_tree_rebuild_raise_fail_blocker(
        const char *fail_reason, int fail_height, int total_commitments,
        int mismatches, const struct sapling_rebuild_skip_tally *skips)
{
    bool is_root_mismatch = fail_reason &&
        (strstr(fail_reason, "sapling_root_mismatch") != NULL ||
         strcmp(fail_reason, "tip_missing_sapling_root") == 0);
    /* The pre-flight refusal (sapling_rebuild_replay_is_impossible) is the same
     * body-availability fact as a post-hoc mismatch over tolerated skips, just
     * proven from headers before any walk — so it classifies identically, and
     * always with a non-empty absent run by construction. */
    bool bodies_absent = fail_reason &&
        strcmp(fail_reason, SAPLING_REBUILD_REASON_REPLAY_IMPOSSIBLE) == 0;
    bool body_gap = (is_root_mismatch || bodies_absent) &&
                    skips && skips->total > 0;
    /* A fail-reason and a skip-class join are CLOSED-SET identifiers: a
     * reader (operator or test) matches them whole, so a fixed `%.Ns` cap
     * renders a token that names no member of the set it claims to name --
     * `replay_impossible_bodies_absent_below_fi` is not a reason, and it is
     * not one silently. Both therefore carry their FULL width here
     * (SAPLING_REBUILD_REASON_REPLAY_IMPOSSIBLE is 57 bytes; the all-classes
     * join is 48).
     *
     * The field order is the priority order, because a cut can only ever eat
     * the tail: identifiers first, then the "what clears it" clause, then the
     * numeric detail. Realistic mainnet values land at 255 of the 256-byte
     * blocker reason; the formal worst case (every int at INT_MIN) is 277, so
     * the sentence is composed in a local buffer that provably holds it and
     * then fitted by zcl_text_fit(), which leaves a visible "...[cut n/m]"
     * marker and WARNs the whole text rather than cutting in silence. */
    char full[BLOCKER_REASON_MAX + 128];
    char reason[BLOCKER_REASON_MAX];
    if (body_gap)
        snprintf(full, sizeof(full),
                "reason=%s classes=%s; seed anchor_kv or backfill bodies "
                "(height=%d commitments=%d mismatches=%d body_gap=%d "
                "span=[%d..%d])",
                fail_reason ? fail_reason : "unknown",
                skips->classes[0] ? skips->classes : "unknown", fail_height,
                total_commitments, mismatches, skips->total,
                skips->first_height, skips->last_height);
    else
        snprintf(full, sizeof(full),
                "sapling_tree_rebuild fail-closed reason=%s height=%d "
                "commitments=%d mismatches=%d",
                fail_reason ? fail_reason : "unknown", fail_height,
                total_commitments, mismatches);
    (void)zcl_text_fit(reason, sizeof(reason), full, "blocker",
                       "sapling_tree_rebuild.fail_closed.reason");
    enum blocker_class cls = body_gap ? BLOCKER_DEPENDENCY
                           : is_root_mismatch ? BLOCKER_PERMANENT
                                              : BLOCKER_TRANSIENT;
    struct blocker_record rec;
    if (blocker_init(&rec, "sapling_tree_rebuild.fail_closed",
                     "sync.sapling_tree_rebuild", cls, reason))
        blocker_set(&rec);
}

/* Per-class typed accounting for a block the replay could not fold. The old
 * code had four SILENT `continue`s (no index / no body / unmappable file /
 * data-position past the mmap / undeserializable) — a dropped block's shielded
 * commitments then vanished with ZERO accounting, surfacing only ~100k blocks
 * later as an opaque tip-root mismatch. This makes every skip a named,
 * counted event at the EXACT height, so a skipped shielded-output block is
 * never a silent gap.
 *
 * Returns true when the caller MUST fail-closed: when the rebuild endpoint is
 * the coins-applied frontier, every in-range block has by construction been
 * APPLIED (body on disk, data position valid), so a skip there is a real local
 * defect, not a legitimate header-only tail — name it and stop AT the block.
 * When the endpoint is the header tip (legacy/no coins frontier), a header-only
 * tail block genuinely has no body to fold; the skip is TOLERATED (counted +
 * throttled-logged), and the denser per-block root check below still catches
 * any skip that actually dropped commitments, at its exact height. */
bool sapling_rebuild_account_skip(const char *reason_tag, int h,
                                  bool fatal, int *counter,
                                  int *first_skip_h, int *last_skip_h)
{
    (*counter)++;
    if (*first_skip_h < 0)
        *first_skip_h = h;
    *last_skip_h = h;
    /* Throttle: log the first of each class, then every 512th, so a wide
     * header-only tail cannot spam node.log while a lone defect is still
     * always surfaced. */
    if (fatal || *counter == 1 || (*counter % 512) == 0)
        LOG_WARN("sapling_tree_rebuild",
                 "shielded verify: block h=%d skipped — reason=%s "
                 "(class_count=%d)%s", h, reason_tag, *counter,
                 fatal ? " [fail-closed: endpoint is coins-applied frontier, "
                         "every in-range block must have a foldable body]"
                       : " [tolerated: header-tip endpoint]");
    return fatal;
}

/* Resume candidate (0): the CANONICAL Sapling frontier ledger.
 *
 * engine/jobs/src/utxo_apply_anchors.c:fold_sapling is the SINGLE writer of
 * anchor_kv's sapling_anchors table, and it fail-closed verifies
 * incremental_tree_root(tree) == blk->header.hashFinalSaplingRoot on every
 * shielded-commitment block it applies. Its stored frontier is therefore
 * header-bound by construction. The node_state["sapling_tree"] blob and the
 * flat-file checkpoint are SECOND copies of that same fact, and second copies
 * drift: on a cure-seeded datadir both lose their header binding at boot and
 * the replay-from-activation they fall back to is structurally impossible,
 * because the block bodies below the cure anchor are simply not on disk.
 * Reading the canonical ledger is the only resume that can succeed there —
 * per docs/ARCHITECTURE_NORTH_STAR.md, heal by reading the canonical copy,
 * never by replaying a clone.
 *
 * Lock order (docs: LOCK-ORDER LAW): anchor_kv lives in the coins/consensus
 * store, which the reducer drive owns while it holds coins_kv. This runs on a
 * background thread, so it must never take progress_store_tx_lock or the
 * reducer's csr->lock. progress_store_open_reader() returns an INDEPENDENT
 * READONLY SQLite connection to the same file (WAL permits concurrent
 * readers, 25 ms busy timeout); the seed is read once, the connection is
 * closed immediately, and NO lock is held across the multi-minute walk.
 *
 * Fail-closed binding: an anchor row carries no block hash of its own, so
 * sapling_ckpt_verify_binding is called with a NULL checkpoint hash — the
 * reorg gate is skipped and the (stronger) root gate does the work: the
 * frontier's own root MUST equal the header chain's hashFinalSaplingRoot at
 * that height. Anything else — unknown header root, mismatch, height above
 * the rebuild endpoint — is refused and the caller falls through to the
 * existing candidates. */
bool sapling_rebuild_anchor_seed(const struct active_chain *chain,
                                 int chain_tip, int sapling_height,
                                 struct incremental_merkle_tree *tree_out,
                                 int64_t *height_out)
{
    if (!chain || !tree_out || !height_out)
        return false;

    sqlite3 *rdb = progress_store_open_reader();
    if (!rdb)
        return false;  /* store not open (fixture/legacy boot) — not an error */

    struct incremental_merkle_tree t;
    sapling_tree_init(&t);
    int64_t h = -1;
    enum anchor_kv_lookup_result lr =
        anchor_kv_latest_tree(rdb, ANCHOR_POOL_SAPLING, &t, NULL, &h);
    sqlite3_close(rdb);

    if (lr != ANCHOR_KV_FOUND)
        return false;
    if (h <= (int64_t)sapling_height)
        return false;  /* nothing above activation to resume from */
    if (h > (int64_t)chain_tip) {
        LOG_WARN("sapling_tree_rebuild",
                 "sapling_tree_rebuild: refusing anchor_kv frontier h=%lld "
                 "(above rebuild endpoint %d)", (long long)h, chain_tip);
        return false;
    }

    const struct block_index *abi = active_chain_at(chain, (int)h);
    bool root_known = sapling_rebuild_header_root_known(abi);
    struct uint256 seed_root;
    incremental_tree_root(&t, &seed_root);
    enum sapling_ckpt_verdict v = sapling_ckpt_verify_binding(
        h, &seed_root, NULL, (int64_t)chain_tip, NULL, false,
        root_known ? &abi->hashFinalSaplingRoot : NULL, root_known);
    if (v != SAPLING_CKPT_OK) {
        LOG_WARN("sapling_tree_rebuild",
                 "sapling_tree_rebuild: refusing anchor_kv frontier h=%lld "
                 "(%s)", (long long)h, sapling_ckpt_verdict_str(v));
        return false;
    }

    *tree_out = t;
    *height_out = h;
    return true;
}
