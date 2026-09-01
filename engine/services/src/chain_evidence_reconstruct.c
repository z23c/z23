/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:internal-reconcile-seam
// This is an internal chain-evidence reconciliation helper, not a new service
// surface. Its single fallible entrypoint already carries the failure reason with the
// failure via the reason_out[192] out-parameter (the caller freezes
// with that precise string), matching the controller's existing
// reconcile contract. struct zcl_result would not improve it.
/*
 * Startup reconcile + active-tip evidence reconstruction — the recovery half
 * of the chain evidence controller. After a chain_restore the in-memory
 * active tip can be hash-consistent (tip_hash == coins_best_block ==
 * active_tip hash) yet carry no evidence record and/or nChainWork==0. Rather
 * than freeze a recoverable tip, we RECOMPUTE what is missing and publish
 * honest, low-trust LOCAL_IMPORT evidence so the node can advance. Only a
 * tip that genuinely cannot be proven consistent freezes — always with a
 * precise, non-empty reason (the no-silent-halt mandate). Background
 * validation later upgrades trust.
 */

#include "services/chain_evidence_authority_service.h"
#include "services/chain_evidence_persistence_service.h"
#include "chain_evidence_reconstruct.h"

#include "models/database.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static bool cer_u256_equal(const struct uint256 *a, const struct uint256 *b)
{
    return a && b && memcmp(a->data, b->data, 32) == 0;
}

static bool cer_persist_i64(struct chain_evidence_controller *a,
                            const char *key, int64_t v)
{
    return a && a->ndb &&
           chain_evidence_state_set_int_retry(a->ndb, key, v,
                                              "cec_reconstruct").ok;
}

static bool cer_persist_blob(struct chain_evidence_controller *a,
                             const char *key, const void *value, size_t len)
{
    return a && a->ndb &&
           chain_evidence_state_set_retry(a->ndb, key, value, len,
                                          "cec_reconstruct").ok;
}

static bool cer_load_u256(struct node_db *ndb, const char *key,
                          struct uint256 *out)
{
    size_t len = 0;
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    return ndb && node_db_state_get(ndb, key, out->data, 32, &len) &&
           len == 32;
}

static int cer_state_get_i32(struct node_db *ndb, const char *key, int def)
{
    int64_t v = def;
    if (ndb)
        (void)node_db_state_get_int(ndb, key, &v);
    return (int)v;
}

/* Field-wise record equality: the struct carries enum/bool padding, so a
 * memcmp over the raw bytes would compare indeterminate padding bytes. */
static bool cer_record_equal(const struct chain_evidence_record *a,
                             const struct chain_evidence_record *b)
{
    return a->source_class == b->source_class &&
           a->publish_state == b->publish_state &&
           a->header_ancestry_linked == b->header_ancestry_linked &&
           a->chainwork_recomputed == b->chainwork_recomputed &&
           a->nakamoto_selected_best_work == b->nakamoto_selected_best_work &&
           a->block_bytes_hash_checked == b->block_bytes_hash_checked &&
           a->utxo_sha3_verified == b->utxo_sha3_verified &&
           a->mmb_flyclient_proof_verified ==
               b->mmb_flyclient_proof_verified &&
           a->chunk_hash_coverage_verified ==
               b->chunk_hash_coverage_verified &&
           a->full_validation_complete == b->full_validation_complete;
}

/* Ancestry walk: tip must be canonical in the block map and link, by
 * strictly decreasing height, to genesis (height 0 with no pprev). */
static bool cer_tip_ancestry_linked(struct chain_state_repository *csr,
                                    struct block_index *tip)
{
    if (!tip || !tip->phashBlock)
        return false;
    if (csr && csr->block_map &&
        block_map_find(csr->block_map, tip->phashBlock) != tip)
        return false;
    for (struct block_index *p = tip; p; p = p->pprev) {
        if (!p->phashBlock)
            return false;
        if (csr && csr->block_map &&
            block_map_find(csr->block_map, p->phashBlock) != p)
            return false;
        if (p->nHeight == 0)
            return p->pprev == NULL;
        if (!p->pprev || p->pprev->nHeight != p->nHeight - 1)
            return false;
    }
    return false;
}

/* Recompute nChainWork for `tip` from the deepest ancestor that already
 * carries work (the "anchor") or from genesis, accumulating GetBlockProof
 * forward. Returns false only when an ancestry link breaks before reaching
 * a worked ancestor / genesis — i.e. the chain genuinely cannot be proven.
 * On success tip->nChainWork (and zero-work ancestors above the anchor)
 * are filled in. */
static bool cer_recompute_chainwork_from_ancestry(struct block_index *tip)
{
    if (!tip)
        return false;

    enum { CER_MAX_REWORK_DEPTH = 4096 };
    struct block_index *chainbuf[CER_MAX_REWORK_DEPTH];
    size_t n = 0;
    struct block_index *base = NULL;
    for (struct block_index *p = tip; p; p = p->pprev) {
        if (n >= CER_MAX_REWORK_DEPTH)
            return false;
        chainbuf[n++] = p;
        if (!arith_uint256_is_zero(&p->nChainWork) || p->nHeight == 0) {
            base = p;          /* worked ancestor, or genesis */
            break;
        }
        if (!p->pprev)
            return false;      /* ancestry broken — cannot prove work */
    }
    if (!base || chainbuf[n - 1] != base)
        return false;

    struct block_index *anchor =
        arith_uint256_is_zero(&base->nChainWork) ? NULL : base;
    for (size_t i = n; i-- > 0;) {
        struct block_index *b = chainbuf[i];
        if (b == anchor)
            continue;          /* keep authoritative work */
        struct arith_uint256 proof = GetBlockProof(b);
        if (b->pprev)
            arith_uint256_add(&b->nChainWork, &b->pprev->nChainWork, &proof);
        else
            b->nChainWork = proof;   /* genesis */
    }
    return !arith_uint256_is_zero(&tip->nChainWork);
}

bool cec_reconstruct_active_tip_evidence(
    struct chain_evidence_controller *authority,
    struct block_index *active_tip,
    const struct chain_state_view *csv,
    bool drift_refused,
    char reason_out[192])
{
    if (reason_out)
        reason_out[0] = '\0';
    if (!authority || !authority->ndb || !active_tip ||
        !active_tip->phashBlock || !csv || csv->tip_height < 0) {
        if (reason_out)
            snprintf(reason_out, 192, "active_tip_reconstruct_null_arg");
        return false;
    }

    /* The block-index evidence we are about to publish proves the TIP:
     * its PoW-bearing header links to genesis (ancestry) and carries the
     * most accumulated work (chainwork). The csr active-tip hash must
     * match the in-memory tip — that IS part of the tip's identity, so a
     * mismatch is a genuine contradiction we must not publish. */
    if (!cer_u256_equal(&csv->tip_hash, active_tip->phashBlock)) {
        if (reason_out)
            snprintf(reason_out, 192,
                     "active_tip_hash != csr_tip_hash (h=%d)",
                     active_tip->nHeight);
        return false;
    }
    /* The coins (UTXO) best-block cursor is a PROJECTION that trails or,
     * on a torn restart, transiently overshoots the tip — it is NOT part
     * of the tip's block-index evidence and must NOT gate it. reconcile_
     * startup already classifies a coins/active-tip mismatch as recoverable
     * lag ("deferring to next commit"); this once contradicted that policy
     * by hard-freezing here, parking a provable tip behind its own lagging
     * cursor. Publishing the tip is correct regardless of cursor position:
     * if coins is behind it catches up on the next commit; if it overshot
     * (the BIP30 self-write wedge) connect_block's self-write tolerance
     * rewinds it. Log the divergence and proceed. */
    if (!cer_u256_equal(&csv->coins_best_block, active_tip->phashBlock)) {
        LOG_WARN("cec",
                 "[cec] reconstruct: coins_best_block cursor != active tip "
                 "h=%d — recoverable projection lag/overshoot; publishing "
                 "tip evidence and letting the cursor reconcile",
                 active_tip->nHeight);
    }

    /* Ancestry must link to genesis. After a restore it usually does; if
     * it doesn't, we cannot prove the tip — freeze with reason. */
    if (!cer_tip_ancestry_linked(authority->csr, active_tip)) {
        if (reason_out)
            snprintf(reason_out, 192,
                     "active_tip_ancestry_unlinkable (h=%d)",
                     active_tip->nHeight);
        return false;
    }

    /* Recompute chainwork if missing — a restored tip frequently carries
     * nChainWork==0 (loader hadn't propagated work). Recoverable. */
    if (arith_uint256_is_zero(&active_tip->nChainWork) &&
        !cer_recompute_chainwork_from_ancestry(active_tip)) {
        if (reason_out)
            snprintf(reason_out, 192,
                     "active_tip_chainwork_unrecoverable (h=%d)",
                     active_tip->nHeight);
        return false;
    }

    /* Refused-rewind mode: reconcile found the persisted tip AHEAD of the
     * in-memory tip and refused to rewrite it downward. The in-memory tip
     * is now PROVEN (hash-consistent, ancestry-linked, chainwork
     * recomputed) — enough for the caller's stale-freeze lift — but every
     * persist below would rewrite the higher persisted tip down.
     * Validation-only. */
    if (drift_refused)
        return true;

    /* Honest classification: recovered from local disk, NOT P2P-selected
     * or byte-verified. Set ONLY the flags actually established (ancestry
     * + chainwork); leave block_bytes_hash_checked /
     * nakamoto_selected_best_work / utxo_sha3_verified FALSE — background
     * validation upgrades them. */
    struct chain_evidence_record reconstructed = {
        .source_class = CEC_SOURCE_CLASS_LOCAL_IMPORT,
        .publish_state = CEC_PUBLISH_LOCAL_EVIDENCE,
        .header_ancestry_linked = true,
        .chainwork_recomputed = true,
    };

    /* Idempotence: when the persisted evidence already equals what this
     * exact tip would persist, re-writing is a no-op rebuild loop. Skip
     * the writes; transition-log once per height so the repeat stays
     * visible without re-firing identically forever. utxo_max_height is
     * the discriminator that the FULL persist chain below already ran for
     * this tip (a reconcile drift-update re-anchors hash+height alone, and
     * the record content is constant — those three alone cannot prove it). */
    struct chain_evidence_record persisted;
    struct uint256 persisted_tip;
    if (chain_evidence_store_load(authority->ndb, "cec.active_tip_evidence",
                                  &persisted).ok &&
        cer_record_equal(&persisted, &reconstructed) &&
        cer_load_u256(authority->ndb, "cec.active_tip_hash",
                      &persisted_tip) &&
        cer_u256_equal(&persisted_tip, active_tip->phashBlock) &&
        cer_state_get_i32(authority->ndb, "cec.active_tip_height", -1) ==
            active_tip->nHeight &&
        cer_state_get_i32(authority->ndb, "cec.utxo_max_height", -1) ==
            active_tip->nHeight &&
        cer_state_get_i32(authority->ndb,
                          "cec.repaired_active_tip_evidence", 0) == 1) {
        static _Atomic int64_t g_idem_warned_h = INT64_MIN;
        if (atomic_exchange(&g_idem_warned_h, (int64_t)active_tip->nHeight)
            != (int64_t)active_tip->nHeight)
            LOG_WARN("cec", "[cec] reconstruct: persisted evidence already "
                     "matches reconstruction (h=%d) — idempotent, skipping "
                     "rewrites", active_tip->nHeight);
        return true;
    }

    return chain_evidence_controller_mark_block_evidence(
               authority, active_tip->phashBlock, &reconstructed).ok &&
           cer_persist_blob(authority, "cec.active_tip_hash",
                            active_tip->phashBlock->data, 32) &&
           cer_persist_i64(authority, "cec.active_tip_height",
                           active_tip->nHeight) &&
           cer_persist_i64(authority, "cec.coins_best_block_height",
                           chain_evidence_clamp_coins_height_to_frontier(
                               authority, active_tip->nHeight)) &&
           cer_persist_i64(authority, "cec.utxo_max_height",
                           active_tip->nHeight) &&
           cer_persist_i64(authority, "cec.publish_state",
                           CEC_PUBLISH_LOCAL_EVIDENCE) &&
           cer_persist_i64(authority, "cec.active_tip_source_class",
                           CEC_SOURCE_CLASS_LOCAL_IMPORT) &&
           cer_persist_i64(authority, "cec.repaired_active_tip_evidence", 1) &&
           chain_evidence_store_persist(authority,
                            "cec.block_index_evidence_state",
                            &reconstructed).ok &&
           chain_evidence_store_persist(authority, "cec.active_tip_evidence",
                            &reconstructed).ok;
}

/* ── startup reconcile (single entry, from controller init) ──────────── */

/* Process-lifetime once-guard. The controller is (re)constructed by every
 * health probe, condition poll, event request and diagnostics dump;
 * re-running the startup reconcile per construction re-fired the same
 * drift/coins WARNs forever at a held tip. The guard is claimed only once a
 * real tip is visible, so an early empty-view construction (mid-boot,
 * before chain restore) cannot consume the only run. */
static _Atomic bool g_cec_startup_reconciled;

void chain_evidence_request_startup_reconcile(const char *why)
{
    LOG_INFO("cec", "[cec] startup reconcile re-armed (%s) — next "
             "controller construction re-derives active-tip evidence",
             why ? why : "unspecified");
    atomic_store(&g_cec_startup_reconciled, false);
}

#ifdef ZCL_TESTING
void chain_evidence_controller_test_reset_startup_reconcile(void)
{
    chain_evidence_request_startup_reconcile("test_reset");
}
#endif

/* coins-mismatch WARN de-storm (tip_finalize_stage idiom): log the first
 * occurrence and every height transition (reporting the prior height's
 * suppressed count); identical repeats only count, with a 300 s keep-alive
 * carrying repeated=N. Touched only under the once-guard above (one
 * reconcile run per process; tests reset between cases). */
static struct { int64_t h; uint64_t reps; int64_t last_log; }
    g_coins_warn = { .h = -1 };

static void cec_warn_coins_mismatch(int tip_height)
{
    int64_t now = platform_time_wall_unix();
    if (g_coins_warn.h != (int64_t)tip_height) {
        LOG_WARN("cec", "[cec] reconcile_startup: coins_best_block != "
                 "active_tip hash (transient or post-shutdown lag) h=%d — "
                 "deferring to next commit (prior h=%lld repeated=%llu)",
                 tip_height, (long long)g_coins_warn.h,
                 (unsigned long long)g_coins_warn.reps);
        g_coins_warn.h = tip_height;
        g_coins_warn.reps = 0;
        g_coins_warn.last_log = now;
        return;
    }
    g_coins_warn.reps++;
    if (now - g_coins_warn.last_log < 300)
        return;
    LOG_WARN("cec", "[cec] reconcile_startup: coins_best_block != active_tip "
             "hash h=%d still unresolved (repeated=%llu)",
             tip_height, (unsigned long long)g_coins_warn.reps);
    g_coins_warn.last_log = now;
}

/* Startup acceptance for previously-reconstructed evidence. A LOCAL_IMPORT
 * record with verified ancestry+chainwork is exactly what reconstruction
 * persists — it can NEVER satisfy
 * chain_evidence_record_has_block_index_required (it honestly leaves the
 * nakamoto/bytes flags false until background validation upgrades them), so
 * gating reconcile on the strict predicate alone re-triggered reconstruction
 * on every run forever. Accept the repaired record here ONLY together with
 * the repaired marker and a persisted-tip-hash match (checked by the
 * caller); promote_tip keeps the strict gate. */
static bool cec_record_is_reconciled_local_import(
    const struct chain_evidence_record *ev)
{
    return ev->source_class == CEC_SOURCE_CLASS_LOCAL_IMPORT &&
           ev->publish_state == CEC_PUBLISH_LOCAL_EVIDENCE &&
           ev->header_ancestry_linked &&
           ev->chainwork_recomputed;
}

void cec_reconcile_startup(struct chain_evidence_controller *authority)
{
    if (!authority || !authority->ndb || !authority->csr)
        return;

    /* A persisted freeze is advisory, not permanent. We always re-derive
     * evidence for the current active tip below; if it proves consistent
     * we LIFT the freeze (a stale freeze must not outlive the condition
     * that caused it). If it genuinely cannot be proven, reconstruct
     * re-freezes with a precise reason. This is what keeps a frozen node
     * self-healing instead of silently parked forever. */
    bool was_frozen = (authority->state == CEC_CONTRADICTION_FROZEN);

    struct chain_state_view csv;
    memset(&csv, 0, sizeof(csv));
    csr_snapshot(authority->csr, &csv);
    if (csv.tip_height < 0)
        return;

    struct block_index *active_tip = authority->csr->chain_active
        ? active_chain_tip(authority->csr->chain_active) : NULL;
    if (!active_tip || !active_tip->phashBlock)
        return;

    if (atomic_exchange(&g_cec_startup_reconciled, true))
        return;

    struct uint256 persisted_hash;
    bool has_persisted_hash =
        cer_load_u256(authority->ndb, "cec.active_tip_hash",
                      &persisted_hash);
    int persisted_height = cer_state_get_i32(authority->ndb,
                                             "cec.active_tip_height", -1);
    struct chain_evidence_record active_evidence;
    bool has_active_evidence =
        chain_evidence_store_load(authority->ndb, "cec.active_tip_evidence",
                      &active_evidence).ok;

    /* Evaluated on the AS-LOADED keys: a drift-update below re-anchors the
     * persisted hash to the in-memory tip, but any persisted evidence was
     * derived for the OLD hash, so acceptance must not survive the
     * update (reconstruct re-derives for the new tip instead). */
    bool persisted_tip_matches = has_persisted_hash &&
        cer_u256_equal(&persisted_hash, active_tip->phashBlock);

    /* Refusing to rewind the persisted high tip skips ONLY the
     * persist-update: evidence reconstruct and the stale-freeze lift below
     * still run against the in-memory tip (drift_refused keeps reconstruct
     * from persisting the lower tip). An early return here silently parked
     * frozen nodes forever behind a stale higher persisted tip. */
    bool drift_refused = false;
    if (has_persisted_hash && !persisted_tip_matches) {
        if (persisted_height > active_tip->nHeight) {
            LOG_WARN("cec", "[cec] startup tip drift: refusing to rewrite "
                     "persisted high tip h=%d down to in-memory h=%d — "
                     "continuing reconcile without the persist-update",
                     persisted_height, active_tip->nHeight);
            drift_refused = true;
        } else {
            char old_hex[65], new_hex[65];
            uint256_get_hex(&persisted_hash, old_hex);
            uint256_get_hex(active_tip->phashBlock, new_hex);
            LOG_WARN("cec", "[cec] startup tip drift: persisted=%s in-memory=%s — " "updating persisted to in-memory (h=%d)", old_hex, new_hex, active_tip->nHeight);
            cer_persist_blob(authority, "cec.active_tip_hash",
                             active_tip->phashBlock,
                             sizeof(*active_tip->phashBlock));
            cer_persist_i64(authority, "cec.active_tip_height",
                            active_tip->nHeight);
        }
    }
    if (!drift_refused && persisted_height >= 0 &&
        persisted_height != active_tip->nHeight) {
        if (persisted_height > active_tip->nHeight) {
            LOG_WARN("cec", "[cec] startup tip drift: refusing lower height "
                     "h=%d -> h=%d — continuing reconcile without the "
                     "persist-update",
                     persisted_height, active_tip->nHeight);
            drift_refused = true;
        } else {
            LOG_WARN("cec", "[cec] startup tip drift: persisted_height=%d " "in-memory_height=%d — updating persisted", persisted_height, active_tip->nHeight);
            cer_persist_i64(authority, "cec.active_tip_height",
                            active_tip->nHeight);
        }
    }
    /* coins_best_block lagging active_tip is recoverable on the running
     * node — the next block commit advances the coins cursor. Reaching
     * this point with a mismatch during reconcile_startup almost always
     * means the controller observed a transient mid-boot state (coins
     * view loaded before active chain restored, or vice versa). Hard
     * contradictions where the persisted active_tip_hash itself diverges
     * are still caught above. Log (de-stormed) and continue. */
    if (!cer_u256_equal(&csv.coins_best_block, active_tip->phashBlock))
        cec_warn_coins_mismatch(active_tip->nHeight);
    /* Derived-state lag is not a contradiction. After a clean shutdown the
     * persisted pindex_best_header / blocks-table max can be behind the
     * active tip; the active tip is the source of truth. Self-heal
     * pindex_best_header forward and log a one-liner; the lagging signal
     * will catch up via P2P / projection. A freeze here was sticky and
     * required manual node.db surgery to clear. */
    if (csv.header_height >= 0 && csv.header_height < active_tip->nHeight) {
        LOG_INFO("cec", "[cec] reconcile_startup: pindex_best_header h=%d behind " "active_tip h=%d — advancing in-memory tracker", csv.header_height, active_tip->nHeight);
        struct chain_state_header_commit header_commit = {
            .new_header_tip = active_tip,
            .reason = "cec_startup_reconcile",
        };
        enum csr_result header_rc = csr_commit_header_tip(
            authority->csr, &header_commit);
        if (header_rc != CSR_OK) {
            LOG_WARN("cec",
                     "reconcile_startup: header promotion refused h=%d code=%s",
                     active_tip->nHeight, csr_result_name(header_rc));
            drift_refused = true;
        }
    }
    if (csv.sql_max_height >= 0 && csv.sql_max_height < active_tip->nHeight) {
        LOG_INFO("cec", "[cec] reconcile_startup: blocks.max_height=%lld behind " "active_tip h=%d — projection will backfill", (long long)csv.sql_max_height, active_tip->nHeight);
    }

    bool evidence_repaired = cer_state_get_i32(authority->ndb,
        "cec.repaired_active_tip_evidence", 0) == 1;
    bool tip_evidence_ok =
        has_active_evidence &&
        (chain_evidence_record_has_block_index_required(&active_evidence) ||
         (evidence_repaired && persisted_tip_matches &&
          cec_record_is_reconciled_local_import(&active_evidence)));
    if (!tip_evidence_ok) {
        char reason[192];
        if (cec_reconstruct_active_tip_evidence(authority, active_tip, &csv,
                                                drift_refused, reason)) {
            tip_evidence_ok = true;
        } else {
            /* Reconstruct only fails when the tip genuinely cannot be
             * proven consistent. It always fills a precise reason; never
             * freeze with an empty/generic string (that produces a halt
             * that does not name itself). */
            if (reason[0] == '\0')
                snprintf(reason, sizeof(reason),
                         "active_tip_evidence_unrecoverable (h=%d)",
                         active_tip->nHeight);
            chain_evidence_controller_freeze(authority, reason);
            return;
        }
    }

    /* The active tip now carries valid block-index evidence (reconstructed
     * this boot or already present). If we entered frozen, that freeze is
     * stale — the tip is provably consistent — so lift it and let the node
     * publish and advance. */
    if (was_frozen && tip_evidence_ok) {
        LOG_WARN("cec",
                 "[cec] lifting stale freeze: active tip h=%d is provably "
                 "consistent (evidence re-derived) — clearing "
                 "contradiction and resuming",
                 active_tip->nHeight);
        authority->state = CEC_EMPTY;
        memset(authority->contradiction_reason, 0,
               sizeof(authority->contradiction_reason));
        (void)chain_evidence_state_set_retry(
            authority->ndb, "cec.sync_state",
            "empty", strlen("empty") + 1,
            "cec_reconcile_startup");
        (void)chain_evidence_state_set_retry(
            authority->ndb, "cec.contradiction_reason", "", 1,
            "cec_reconcile_startup");
        (void)cer_persist_i64(authority, "cec.publish_state",
                              CEC_PUBLISH_LOCAL_EVIDENCE);
    }
}
