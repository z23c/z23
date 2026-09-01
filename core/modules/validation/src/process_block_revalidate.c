/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * process_block_revalidate — see header for the verify-never-trust
 * contract. */

#include "validation/process_block_revalidate.h"

#include "chain/chain.h"
#include "core/uint256.h"
/* The verify-never-trust contract for clearing BLOCK_FAILED_VALID requires
 * (a) sufficient oracle consensus on the block hash and (b) routing the
 * post-clear connect through the activation controller's mutex. Both services
 * are app-layer concerns conceptually, but the actual nStatus mutation and
 * durable projection emission belong to validation. Splitting this into two files
 * across layers (a validation low-level primitive plus an app-services
 * orchestrator) adds two files for no behavioral gain. Tagged so the
 * lib_layering gate doesn't have to grow its baseline. */
#include "services/chain_activation_service.h"  // lib-layer-ok:wave-m-revalidate
#include "services/quorum_oracle_service.h"        // lib-layer-ok:wave-m-revalidate
#include "jobs/block_header_emit.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include "process_block_internal.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

const char *reval_result_name(enum reval_result r)
{
    switch (r) {
        case REVAL_NOT_ATTEMPTED:        return "not_attempted";
        case REVAL_NO_FAILURE:           return "no_failure";
        case REVAL_HEIGHT_NOT_FOUND:     return "height_not_found";
        case REVAL_EVIDENCE_INSUFFICIENT:return "evidence_insufficient";
        case REVAL_EVIDENCE_DISAGREES:   return "evidence_disagrees";
        case REVAL_PERSIST_FAILED:       return "persist_failed";
        case REVAL_CONNECT_FAILED:       return "connect_failed";
        case REVAL_RECOVERED:            return "recovered";
    }
    return "?";
}

/* Iterate block_map looking for a pindex at exactly `target_height` that
 * carries BLOCK_FAILED_VALID. Returns NULL if no such entry exists.
 *
 * Multiple pindex entries can share a height (forks). We prefer the
 * entry whose immediate ancestry chains back through the active chain
 * tip, but the simpler "first FAILED_VALID match" is sufficient for the
 * wedge case where the active chain is stuck and the failed block is
 * the only obstruction. */
static struct block_index *find_failed_pindex_at_height(
    struct main_state *ms, int target_height)
{
    if (!ms) return NULL;
    size_t iter = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p) continue;
        if (p->nHeight != target_height) continue;
        if (!(p->nStatus & BLOCK_FAILED_VALID)) continue;
        return p;
    }
    return NULL;
}

/* Find a FAILED pindex at target_height whose hash matches the supplied
 * lowercase-hex hash. When multiple pindex entries share a height
 * (competing forks), prefer the one the oracle has named as canonical.
 * Returns NULL if no such matching FAILED entry exists. */
static struct block_index *find_failed_pindex_by_hash(
    struct main_state *ms, int target_height, const char *want_hex)
{
    if (!ms || !want_hex || !want_hex[0]) return NULL;
    size_t iter = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p || !p->phashBlock) continue;
        if (p->nHeight != target_height) continue;
        if (!(p->nStatus & BLOCK_FAILED_VALID)) continue;
        char got[65];
        uint256_get_hex(p->phashBlock, got);
        if (strcasecmp(got, want_hex) == 0)
            return p;
    }
    return NULL;
}

enum reval_result process_block_revalidate(int target_height,
                                            struct main_state *ms,
                                            struct uint256 *out_hash)
{
    if (out_hash) memset(out_hash, 0, sizeof(*out_hash));
    if (!ms) {
        return REVAL_NOT_ATTEMPTED;
    }
    if (target_height < 0) {
        return REVAL_NOT_ATTEMPTED;
    }

    /* ── Step 1: any failed pindex at this height? Short-circuit if not. */
    struct block_index *any_failed =
        find_failed_pindex_at_height(ms, target_height);
    if (!any_failed) {
        /* Either there's no entry at this height, or none of the entries
         * have BLOCK_FAILED_VALID set. Either is a non-failure. */
        return REVAL_HEIGHT_NOT_FOUND;
    }

    /* ── Step 2: query the quorum oracle for evidence ────────────────── */
    struct quorum_oracle_result qr;
    memset(&qr, 0, sizeof(qr));
    struct zcl_result probe_r = quorum_oracle_probe(target_height, &qr);
    if (!probe_r.ok) {
        fprintf(stderr,  // obs-ok:revalidate-probe-failure
                "[revalidate] h=%d: quorum_oracle_probe failed (code=%d %s); "
                "leaving FAILED set\n", target_height,
                probe_r.code, probe_r.message);
        return REVAL_EVIDENCE_INSUFFICIENT;
    }

    /* Pick the FAILED pindex that matches the oracle's canonical hash
     * when possible — at heights with competing forks the block_map can
     * carry multiple pindex entries; we want to clear the FAILED bit on
     * the one the authoritative source agrees with, not just the first
     * one the iterator returned. Falls back to `any_failed` if the
     * oracle's hash doesn't match any FAILED entry (the disagreement
     * path will reject below). */
    struct block_index *failed_pindex = any_failed;
    {
        const char *oracle_hash = NULL;
        if (qr.verdict == QO_VERDICT_QUORUM_MATCH &&
            qr.winning_hash_hex[0]) {
            oracle_hash = qr.winning_hash_hex;
        } else if (qr.by_source[QO_SRC_ZCLASSICD].present &&
                   !qr.by_source[QO_SRC_ZCLASSICD].error &&
                   qr.by_source[QO_SRC_ZCLASSICD].hash_hex[0]) {
            oracle_hash = qr.by_source[QO_SRC_ZCLASSICD].hash_hex;
        }
        if (oracle_hash) {
            struct block_index *match =
                find_failed_pindex_by_hash(ms, target_height, oracle_hash);
            if (match) failed_pindex = match;
        }
    }
    if (failed_pindex->phashBlock && out_hash) {
        *out_hash = *failed_pindex->phashBlock;
    }
    if (!(failed_pindex->nStatus & BLOCK_FAILED_VALID)) {
        return REVAL_NO_FAILURE;
    }

    /* Compute our own pindex hash once — needed by every evidence
     * pathway below. */
    char our_hash_hex[65];
    our_hash_hex[0] = '\0';
    if (failed_pindex->phashBlock) {
        uint256_get_hex(failed_pindex->phashBlock, our_hash_hex);
    }

    /* ── Step 2a: evidence pathway resolution ────────────────────────
     *
     * Two acceptance pathways, both preserving verify-never-trust:
     *
     *   (A) MULTI-ORACLE QUORUM (original 2-of-N contract): ≥min_agree
     *       independent sources return the same hash. This multi-oracle path
     *       is required when we have a peer mesh.
     *
     *   (B) SINGLE-SOURCE LOCAL AUTHORITY (personal sovereignty stack):
     *       on a personal-stack node the always-on local `zclassicd`
     *       (reached in-process via legacy_mirror + RPC) IS the local
     *       authority. When (i) zclassicd's QO_SRC_ZCLASSICD source
     *       returned a hash, (ii) that hash matches our failed pindex's
     *       hash, AND (iii) the LOCAL source (our own active_chain)
     *       has NO opinion at this height — i.e. our tip is below
     *       target_height so there is no contradicting local vote —
     *       we accept zclassicd's verdict as sufficient evidence to
     *       re-attempt validation.
     *
     *       This is NOT skip-validation: the post-clear `connect_block`
     *       runs the full Equihash / scripts / Sapling validator and
     *       will re-mark BLOCK_FAILED_VALID if the block genuinely
     *       fails. The single-source verdict only unblocks the gate
     *       so the validator can re-run. The "live at tip via the
     *       always-on local authority" mandate (CLAUDE.md, "Personal
     *       Sovereignty Stack") requires this — otherwise a personal
     *       node with no zcl23 peers can never auto-clear a stale
     *       FAILED bit and the chain silently halts.
     *
     *       Safety boundaries (every one must hold):
     *         - QO_SRC_LOCAL must NOT be present at this height (no
     *           contradicting local opinion).
     *         - QO_SRC_ZCLASSICD must be present, error-free, and
     *           return exactly our pindex's hash.
     *         - Cleared block must still pass full connect_block.
     */
    bool accepted = false;
    const char *evidence_path = NULL;

    if (qr.verdict == QO_VERDICT_QUORUM_MATCH) {
        /* Multi-oracle quorum already verified ≥min_agree sources
         * agree on `qr.winning_hash_hex`. Verify it matches us. */
        if (our_hash_hex[0] != '\0' &&
            strcasecmp(our_hash_hex, qr.winning_hash_hex) == 0) {
            accepted = true;
            evidence_path = "multi_oracle_quorum";
        } else {
            fprintf(stderr,  // obs-ok:revalidate-disagreement
                    "[revalidate] h=%d: oracle agreed on %s but our "
                    "FAILED pindex is %s — we're on a fork; leaving "
                    "FAILED set so chain selection reorgs through a "
                    "different mechanism\n",
                    target_height, qr.winning_hash_hex,
                    our_hash_hex[0] ? our_hash_hex : "(no hash)");
            return REVAL_EVIDENCE_DISAGREES;
        }
    }

    if (!accepted) {
        /* Pathway (B): single-source local authority. The contract:
         * zclassicd matches us, and LOCAL has no opinion. */
        const struct quorum_oracle_source_result *zd =
            &qr.by_source[QO_SRC_ZCLASSICD];
        const struct quorum_oracle_source_result *lo =
            &qr.by_source[QO_SRC_LOCAL];
        bool zd_ok      = zd->present && !zd->error && zd->hash_hex[0];
        bool local_mute = !lo->present || lo->error || !lo->hash_hex[0];
        bool zd_agrees_with_us =
            zd_ok && our_hash_hex[0] != '\0' &&
            strcasecmp(zd->hash_hex, our_hash_hex) == 0;
        /* Tip must be strictly below target so LOCAL silence is
         * structural (we genuinely have no opinion), not a bug. */
        int tip_h_check = active_chain_height(&ms->chain_active);
        bool tip_below_target = tip_h_check < target_height;

        if (zd_ok && zd_agrees_with_us && local_mute && tip_below_target) {
            accepted = true;
            evidence_path = "local_authority_zclassicd";
            fprintf(stderr,  // obs-ok:revalidate-local-authority
                    "[revalidate] h=%d: accepting single-source "
                    "local-authority evidence (zclassicd hash=%s "
                    "matches our pindex; LOCAL has no vote; "
                    "active_tip=%d < target=%d). Personal-stack "
                    "sovereignty: zclassicd IS the local authority. "
                    "Verification preserved — connect_block will fully "
                    "re-validate.\n",
                    target_height, our_hash_hex,
                    tip_h_check, target_height);
        } else {
            fprintf(stderr,  // obs-ok:revalidate-no-quorum
                    "[revalidate] h=%d: no acceptable evidence "
                    "(verdict=%d agreeing=%d zd_ok=%d zd_agrees=%d "
                    "local_mute=%d tip_below_target=%d our=%s "
                    "zd=%s); leaving FAILED set\n",
                    target_height, (int)qr.verdict, qr.agreeing_sources,
                    (int)zd_ok, (int)zd_agrees_with_us,
                    (int)local_mute, (int)tip_below_target,
                    our_hash_hex[0] ? our_hash_hex : "(empty)",
                    zd->hash_hex[0] ? zd->hash_hex : "(empty)");
            return REVAL_EVIDENCE_INSUFFICIENT;
        }
    }
    /* ── Step 4: evidence accepted (multi-oracle quorum or single-source
     * local authority on a personal stack). Safe to clear. ───────────── */
    /* Clear BLOCK_FAILED bits on this pindex AND every descendant above
     * the current active tip. Uses the same shape as
     * chain_restore_clear_failed_above_tip in chain_restore_repair.c —
     * proven safe when there's evidence the canonical chain runs
     * through the cleared blocks. The evidence here is the
     * `evidence_path` set above; descendants will be re-validated by
     * the next reducer validation pass and re-marked FAILED
     * individually if any are genuinely invalid. */
    int tip_h = active_chain_height(&ms->chain_active);
    int cleared = 0;
    int persisted = 0;
    int persist_errors = 0;
    size_t iter = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p) continue;
        /* Only clear at-or-above the failed height. Below the active
         * tip we must not touch — those are durable history. */
        if (p->nHeight < target_height) continue;
        if (p->nHeight <= tip_h && p != failed_pindex) continue;
        unsigned was_failed = p->nStatus & BLOCK_FAILED_MASK;
        if (!was_failed) continue;
        p->nStatus &= ~(unsigned)BLOCK_FAILED_MASK;
        cleared++;
        bool projected = block_index_emit_header_event(
            p, "revalidate_persist", NULL, NULL);
        /* Runtime persistence is the append-only event log. Count every
         * failed append and refuse success if none of the cleared entries was
         * made durable; tests without a wired runtime retain their seam. */
        if (g_active_block_tree) {
            if (projected) {
                persisted++;
            } else {
                persist_errors++;
            }
        }
    }

    fprintf(stderr,  // obs-ok:revalidate-cleared
            "[revalidate] h=%d: evidence=%s; cleared %d FAILED entries "
            "(%d persisted, %d errors)\n",
            target_height, evidence_path ? evidence_path : "?",
            cleared, persisted, persist_errors);

    if (cleared > 0 && persisted == 0 && persist_errors > 0) {
        /* Nothing persisted — won't survive a crash. Treat as a failure. */
        return REVAL_PERSIST_FAILED;
    }

    /* ── Step 5: trigger activation. ─────────────────────────────────── */
    /* The activation controller serializes on its own mutex; we call it
     * with NULL block (no specific block to connect — just kick the
     * activation loop to re-evaluate find_most_work_chain with our
     * newly cleared entries). */
    struct chain_activation_controller *ctl = process_block_activation_controller();
    if (!ctl) {
        fprintf(stderr,  // obs-ok:revalidate-no-controller
                "[revalidate] h=%d: no activation controller; cannot "
                "trigger connect — chain will advance on next natural "
                "activation kick\n", target_height);
        /* Still return RECOVERED — we cleared the gate, and the next
         * P2P/watchdog tick will invoke activation naturally. */
        return REVAL_RECOVERED;
    }

    enum activation_state s = activation_get_state(ctl);
    if (s != ACTIVATION_READY && s != ACTIVATION_AT_TIP) {
        fprintf(stderr,  // obs-ok:revalidate-not-ready
                "[revalidate] h=%d: activation state=%s not ready for "
                "kick; leaving cleared and returning RECOVERED — natural "
                "tick will pick up cleared blocks\n",
                target_height, activation_state_name(s));
        return REVAL_RECOVERED;
    }

    /* Kick the engine to reconnect the now-eligible chain. The reducer
     * re-walks the best chain by draining the staged Job pipeline through
     * reducer_kick.
     * outcome stays zeroed (the reducer reports its verdict through the tip
     * advance inspected below); the tail diagnostic reads outcome.result. */
    struct activation_exec_outcome outcome;
    memset(&outcome, 0, sizeof(outcome));
    (void)reducer_kick(ctl);

    /* Inspect: did the chain actually advance? */
    int new_tip_h = active_chain_height(&ms->chain_active);
    if (new_tip_h > tip_h) {
        fprintf(stderr,  // obs-ok:revalidate-success
                "[revalidate] h=%d: chain advanced %d → %d after "
                "revalidation\n", target_height, tip_h, new_tip_h);
        return REVAL_RECOVERED;
    }

    /* Activation ran but tip didn't advance. Either connect_block
     * re-marked FAILED on our cleared block (still genuinely invalid)
     * or some other condition blocked. Re-check the original pindex. */
    if (failed_pindex->nStatus & BLOCK_FAILED_VALID) {
        fprintf(stderr,  // obs-ok:revalidate-remarked
                "[revalidate] h=%d: cleared, retried, connect_block "
                "re-marked FAILED; block is genuinely invalid (or "
                "transient resource failure). Next 900s tick will retry.\n",
                target_height);
        return REVAL_CONNECT_FAILED;
    }

    /* Cleared, activation ran, tip didn't move, but pindex isn't
     * re-marked FAILED. This usually means activation skipped (state
     * transitions, in-flight work, etc.). Treat as RECOVERED — the
     * gate is open, future ticks will advance. */
    fprintf(stderr,  // obs-ok:revalidate-cleared-no-advance
            "[revalidate] h=%d: cleared and persisted; activation kick "
            "didn't advance tip this cycle (result=%d). Next tick will "
            "pick it up.\n", target_height, (int)outcome.result);
    return REVAL_RECOVERED;
}
