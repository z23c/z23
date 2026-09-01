/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Header band backfill — closes the installed-above-frontier header hole.
 *
 * The defect class: cold-import installs a pprev-less island anchor +
 * cursor tip ABOVE the genesis-rooted header frontier, leaving a band of
 * never-requested headers between the contiguous frontier and the island
 * root. Header sync's restart-from-tip policy then kills every
 * conversation that could fill the band ("low batch ... restarting
 * getheaders from tip"), while tip-anchored locators die at the island
 * root and can never name a band block — the hole is permanent by
 * construction.
 *
 * The fix is request-side only (header ACCEPTANCE is untouched):
 *   - syncsvc_header_band_continue: a below-tip batch that extends the
 *     trust-rooted frontier is PROGRESS, not a restart trigger.
 *   - syncsvc_header_band_backfill_anchor: while the band fact is
 *     recorded, periodic getheaders anchor at the contiguous frontier
 *     (the peer forks there and serves the band). The anchor is the
 *     HIGHER of two authorities: the highest populated active-chain
 *     slot AND the index-frontier cursor (slots lag the block index
 *     during the walk; a slot-only anchor livelocks).
 *   - syncsvc_header_band_after_batch: on closure (tip descends
 *     contiguously to a trust root) run a NON-DESTRUCTIVE in-memory
 *     slot-fill (the pprev chain IS contiguous at closure — that is the
 *     closure condition), repropagate chainwork above the SHA3 anchor,
 *     re-derive the band fact, and only then clear the blocker and
 *     unlatch the chain-evidence startup freeze. The boot disk-rebuild
 *     ladder (chain_restore_finalize) is deliberately NOT called here:
 *     band headers are header-only (no BLOCK_HAVE_DATA), so the disk
 *     walk is guaranteed to under-populate, fall into the full blk*.dat
 *     scan, and rewrite pprev=NULL across millions of shared
 *     block_index nodes on the live net thread — the exact
 *     ancestry-tear class this service exists to close.
 *
 * All band facts are DERIVED from pprev contiguity on demand
 * (utxo_recovery_block_ancestry_break); the typed blocker is a loud
 * cache of that derivation, never an authority. */
// one-result-type-ok:band-planner-predicates — these are getheaders
// planner predicates/selectors consumed on the net thread (bool/anchor
// pointer/void closure hook); every refusal that matters travels via
// structured LOG + EV_RECOVERY_ACTION, not a result carrier.

#include "sync/sync_planner.h"

#include "services/chain_evidence_authority_service.h"
#include "services/utxo_recovery_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "jobs/reducer_frontier.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "event/event.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>

/* Band INDEX-frontier cursor — guards the band anchor slot/index
 * divergence livelock: header ACCEPTANCE inserts into the block index
 * WITHOUT populating active-chain slots (slots only move on tip moves /
 * boot restore repair), so an anchor derived from populated slots alone
 * pins one batch behind the index once the walk passes the boot-populated
 * slot extent. The pinned locator makes the peer fork at the stale slot
 * frontier and re-serve the same already-known range forever
 * (accepted=160, newly_added=0), nothing in that batch path populates
 * slots, and the anchor never advances: livelock.
 *
 * The cursor is the index half of the anchor derivation: the highest
 * accepted batch tail that walks pprev-contiguously to a trust root
 * (utxo_recovery_block_trust_rooted) strictly below the island root. It
 * is a HINT, never an authority — re-verified (trust-rooted + below
 * island) at every use, monotone under concurrent peer threads, cleared
 * on band closure. block_index nodes have per-node hashBlock storage
 * stable for the process lifetime, so a stale cursor is droppable, never
 * dangling. */
static _Atomic(struct block_index *) g_band_index_frontier;

/* Monotone cursor advance (CAS loop: a re-served lower batch must never
 * drag the anchor back). `last_header` was vetted by the caller:
 * trust-rooted and strictly below the island root. The const cast is
 * confined here — the anchor is only ever read to build getheaders
 * locators. */
static void band_cursor_advance(const struct block_index *last_header)
{
    struct block_index *cur = atomic_load(&g_band_index_frontier);
    while ((!cur || last_header->nHeight > cur->nHeight) &&
           !atomic_compare_exchange_weak(&g_band_index_frontier, &cur,
                                         (struct block_index *)last_header))
        ;
}

void syncsvc_header_band_reset_for_testing(void)
{
    atomic_store(&g_band_index_frontier, NULL);
}

/* S8: request-side-only predicate for the getheaders interval planner.
 * The band fact IS the typed blocker (set/cleared by the producers and
 * after_batch above) — no re-derivation needed here, matching the same
 * O(1) exit backfill_anchor already relies on. */
bool syncsvc_header_band_hole_open(void)
{
    return blocker_exists(HEADER_BAND_BLOCKER_ID);
}

bool syncsvc_header_band_continue(const struct active_chain *chain,
                                  const struct block_index *last_header)
{
    if (!chain || !last_header)
        return false;

    struct block_index *tip = active_chain_tip(chain);
    if (!tip)
        return false;

    const struct block_index *island_root =
        utxo_recovery_block_ancestry_break(tip);
    if (!island_root)
        return false;          /* tip is trust-rooted — no band exists */
    if (last_header->nHeight >= island_root->nHeight)
        return false;          /* island-side header — not band fill */
    /* The peer cannot buy restart-suppression with a detached low fork:
     * only a batch that extends the trust-rooted frontier is progress. */
    if (!utxo_recovery_block_trust_rooted(last_header))
        return false;  // raw-return-ok:not-trust-rooted-is-a-normal-non-progress-batch

    /* Defensive: a producer or the boot scan normally recorded the band
     * already; derive-and-record here so a runtime-created band is just
     * as loud (registry rate-limits dups). */
    if (!blocker_exists(HEADER_BAND_BLOCKER_ID))
        utxo_recovery_note_band_unrooted_tip(tip, "band_continue");

    /* Advance the index-frontier cursor even when the batch added nothing
     * new (newly_added==0) — an all-known trust-rooted batch still proves
     * the index extends to last_header, and the next request must anchor
     * there (or higher) or the peer re-serves the same range forever. */
    band_cursor_advance(last_header);

    LOG_INFO("headers",
             "header band backfill: continuing from h=%d (island_root=%d)",
             last_header->nHeight, island_root->nHeight);
    return true;
}

struct block_index *syncsvc_header_band_backfill_anchor(
    const struct active_chain *chain)
{
    if (!chain)
        return NULL;
    /* O(1) exit for healthy nodes — the periodic getheaders planner
     * calls this on every kick; no ancestry walk without the band fact. */
    if (!blocker_exists(HEADER_BAND_BLOCKER_ID))
        return NULL;

    struct block_index *tip = active_chain_tip(chain);
    if (!tip)
        return NULL;
    const struct block_index *island_root =
        utxo_recovery_block_ancestry_break(tip);
    if (!island_root)
        return NULL;           /* band closed; after_batch clears the fact */

    /* SLOT half — the highest populated slot below the island root.
     * Sufficient at boot (the restored chain ends there), but it LAGS
     * the block index during the walk: header acceptance inserts into
     * the index only, so a slot-only anchor pins one batch back and the
     * peer re-serves the same known range forever. */
    struct block_index *slot_frontier = NULL;
    for (int h = island_root->nHeight - 1; h >= 0; h--) {
        struct block_index *slot = active_chain_at(chain, h);
        if (!slot)
            continue;
        if (utxo_recovery_block_trust_rooted(slot))
            slot_frontier = slot;
        else
            LOG_WARN("headers",
                     "header band backfill: frontier candidate h=%d below "
                     "island_root=%d is itself not trust-rooted — no "
                     "servable slot anchor", h, island_root->nHeight);
        break;                 /* only the highest populated slot counts */
    }

    /* INDEX half — the cursor band_continue/after_batch advance on
     * EVERY accepted band batch (including all-known newly_added==0
     * ones). Re-verify at use: repair ladders can rewrite ancestry, so
     * a cursor that no longer walks to a trust root or no longer sits
     * below the island root is stale — drop it (CAS: never clobber a
     * concurrent advance) so a lower one can re-establish. */
    struct block_index *cursor = atomic_load(&g_band_index_frontier);
    if (cursor && (cursor->nHeight >= island_root->nHeight ||
                   !utxo_recovery_block_trust_rooted(cursor))) {
        struct block_index *stale = cursor;
        atomic_compare_exchange_strong(&g_band_index_frontier, &stale, NULL);
        cursor = NULL;
    }

    /* Anchor at the HIGHER of the two authorities: anchoring below the
     * index frontier makes the peer fork there and re-serve headers the
     * index already holds. */
    struct block_index *anchor = slot_frontier;
    if (cursor && (!anchor || cursor->nHeight > anchor->nHeight))
        anchor = cursor;
    if (anchor)
        return anchor;

    LOG_WARN("headers",
             "header band backfill: no populated slot below island_root=%d "
             "and no index-frontier cursor — no servable band anchor",
             island_root->nHeight);
    return NULL;
}

/* Closure slot-fill: non-destructive and in-memory only. At closure the
 * tip's pprev chain is contiguous down to the trust root BY DERIVATION
 * (utxo_recovery_block_ancestry_break(tip) == NULL is the closure
 * condition), so slotting it into chain[] is a pure walk-and-store under
 * the writer lock. It only ever stores the tip's own ancestors — never
 * NULL, never a different fork — and never mutates pprev/pskip/nHeight
 * of any shared block_index node, so lock-free readers (reducer stages,
 * RPC, chain-evidence probes) see the old slot or the canonical ancestor,
 * both valid. The walk stops at the compiled SHA3 anchor: a band can
 * only exist above it (the ancestry derivation early-exits there), so
 * slots at or below the anchor are not this hole's to touch. */
static int syncsvc_header_band_fill_slots(struct active_chain *c,
                                          struct block_index *tip,
                                          int32_t stop_height)
{
    int filled = 0;
    zcl_mutex_lock(&c->write_lock);
    struct block_index **arr = c->chain;
    if (arr) {
        int budget = tip->nHeight + 1;   /* cycle defense */
        for (struct block_index *p = tip;
             p && p->nHeight > stop_height && budget-- > 0;
             p = p->pprev) {
            int h = p->nHeight;
            if (h < 0 || h > tip->nHeight)
                break;         /* defensive: never slot a tear shape */
            if (arr[h] != p) {
                arr[h] = p;
                filled++;
            }
        }
    }
    zcl_mutex_unlock(&c->write_lock);
    return filled;
}

void syncsvc_header_band_after_batch(struct main_state *ms,
                                     const struct block_index *last_header)
{
    if (!ms)
        return;
    if (!blocker_exists(HEADER_BAND_BLOCKER_ID))
        return;                /* no band fact — no-op on the hot path */

    struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (!tip)
        return;
    const struct block_index *island_root =
        utxo_recovery_block_ancestry_break(tip);
    if (island_root) {
        /* Band still open — surface fill progress when the batch landed
         * in the band (closure needs the peer to re-serve the island
         * root so accept_block_header hash-binds its pprev). Also
         * advance the index-frontier cursor here: short batches (<160)
         * never reach band_continue (the continuation gate requires a
         * full batch), but they extend the index all the same and the
         * next kick must anchor past them. */
        if (last_header && last_header->nHeight < island_root->nHeight) {
            if (utxo_recovery_block_trust_rooted(last_header))
                band_cursor_advance(last_header);
            LOG_INFO("headers",
                     "header band backfill progress: filled to h=%d "
                     "(island_root=%d)",
                     last_header->nHeight, island_root->nHeight);
        }
        return;
    }

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    const int32_t anchor_h = cp ? cp->height
                                : REDUCER_FRONTIER_TRUSTED_ANCHOR;

    /* Band CLOSED: the tip now descends contiguously to a trust root.
     * 1) Non-destructive in-memory slot-fill (heals getblockhash /
     *    active_chain_at in-process), then pskip for relinked island
     *    nodes (accepted pprev-less, so accept_block_header never built
     *    theirs). Bottom-up so each build reuses the parent's pskip. */
    int filled = syncsvc_header_band_fill_slots(&ms->chain_active, tip,
                                                anchor_h);
    for (int h = anchor_h + 1; h <= tip->nHeight; h++) {
        struct block_index *b = active_chain_at(&ms->chain_active, h);
        if (b && b->pprev && b->pskip == NULL)
            block_index_build_skip(b);
    }

    /* 2) Chainwork repropagation above the attested anchor extent: the
     *    island's work was seeded from a pprev-less anchor (nChainWork=0),
     *    understating every island block. Idempotent for already-correct
     *    chains — same write pattern as the accept_block_header relink. */
    int repropagated = 0;
    for (int h = anchor_h + 1; h <= tip->nHeight; h++) {
        struct block_index *b = active_chain_at(&ms->chain_active, h);
        if (!b || !b->pprev)
            continue;
        struct arith_uint256 proof = GetBlockProof(b);
        arith_uint256_add(&b->nChainWork, &b->pprev->nChainWork, &proof);
        repropagated++;
    }

    /* 3) The clear is bound to the DERIVED fact, never to control flow:
     *    re-derive after the heal and keep the band fact recorded if the
     *    ancestry is somehow torn again (the fill above is non-mutating,
     *    so this holds by construction today — the guard pins the
     *    invariant against any future closure step that touches pprev).
     *    Losing the fact while the tear persists would strand the
     *    backfill driver for the rest of the process lifetime. */
    island_root = utxo_recovery_block_ancestry_break(tip);
    if (island_root) {
        LOG_WARN("headers",
                 "header band close ABORTED: ancestry re-tore during "
                 "closure (island_root=%d tip=%d) — band fact retained, "
                 "backfill stays armed",
                 island_root->nHeight, tip->nHeight);
        return;
    }

    atomic_store(&g_band_index_frontier, NULL);  /* cursor dies with the fact */
    blocker_clear(HEADER_BAND_BLOCKER_ID);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=header_band_closed tip=%d slots_filled=%d "
                "chainwork_blocks=%d",
                tip->nHeight, filled, repropagated);
    LOG_WARN("headers",
             "HEADER BAND CLOSED: tip h=%d now descends contiguously to "
             "its trust root (%d chain slots filled, chainwork "
             "repropagated over %d blocks); requesting chain-evidence "
             "startup re-reconcile",
             tip->nHeight, filled, repropagated);

    /* 4) Unlatch the evidence freeze: the next controller construction
     *    re-runs cec_reconcile_startup once; ancestry now links, so the
     *    stale contradiction_frozen lifts and health recovers. */
    chain_evidence_request_startup_reconcile("header_band_closed");
}
