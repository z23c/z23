/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * ConnectBlock — full block validation against the UTXO set.
 * Consensus checks mirror zclassicd main.cpp:2489-2702. The C23 node
 * layers a few additions on top of the zclassicd set (none relax a
 * zclassicd reject — see CONSENSUS_PARITY_DOCTRINE.md):
 *   - ZIP-209 turnstile checks (Sprout/Sapling pool can't go negative)
 *   - Sapling-root sanity check on the block's final anchor
 *   - BIP30 self-write tolerance for kill-9 recovery (re-apply of a
 *     block's own coinbase is not a duplicate)
 *
 * NEW in this refactor:
 *   - REJECT_IF / REJECT_UNLESS macros (Rails-style DRY)
 *   - Per-input MoneyRange validation
 *   - Validation events via event_emitf()
 *   - Input value < output check (bad-txns-in-belowout) */

#include <stdio.h>
#include <stdatomic.h>
#include "util/log_macros.h"
#include "validation/connect_block.h"
#include "validation/check_block.h"
#include "validation/check_transaction.h"
#include "validation/contextual_check_tx.h"
#include "validation/mirror_consensus.h"
#include "validation/update_coins.h"
#include "validation/sigops.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"
#include "chain/subsidy.h"
#include "chain/checkpoints.h"
#include "consensus/upgrades.h"
#include "validation/main_constants.h"
#include "sapling/incremental_merkle_tree.h"
#include "event/event.h"
#include "util/workpool.h"
#include "util/util.h"

/* ── Parallel script verification ────────────────────────── */

/* Work item for one input's script verification */
struct script_check {
    const struct script *script_sig;
    const struct script *script_pub_key;
    uint32_t flags;
    uint32_t branch_id;
    struct tx_sig_checker tsc;
    struct precomputed_tx_data *txdata; /* shared per-tx, read-only */
};

static bool script_check_fn(void *item)
{
    struct script_check *sc = (struct script_check *)item;
    struct sig_checker checker = tx_make_sig_checker(&sc->tsc);
    ScriptError serror = SCRIPT_ERR_OK;
    return verify_script(sc->script_sig, sc->script_pub_key,
                         sc->flags, &checker, sc->branch_id, &serror);
}

/* Lazy-initialized global workpool for script verification.
 * Workers persist across blocks to avoid thread create/destroy overhead. */
static struct workpool g_script_pool;
static bool g_script_pool_ready = false;

static struct workpool *get_script_pool(void)
{
    if (!g_script_pool_ready) {
        int ncores = GetNumCores();
        if (ncores < 2) ncores = 2;
        if (ncores > 16) ncores = 16;
        /* Queue capacity: large enough for biggest blocks (~5000 inputs) */
        if (workpool_init(&g_script_pool, ncores, 8192, script_check_fn))
            g_script_pool_ready = true;
        else
            return NULL;
    }
    return &g_script_pool;
}

/* Global Sapling tree pointer — set by the reducer/process-block bridge before
 * calling connect_block. NULL during just_check mode. */
static struct incremental_merkle_tree *g_sapling_tree = NULL;

void connect_block_set_sapling_tree(struct incremental_merkle_tree *tree)
{
    g_sapling_tree = tree;
}

/* ── Sapling-root parity enforcement (DEFAULT-OFF) ──────────────────────
 * See connect_block.h for the full contract and the replay-before-enable
 * warning. Default false ⇒ default connect_block behavior is byte-identical
 * to today (still ONLY the all-zeros reject below). */
_Atomic _Bool g_enforce_sapling_root = false;

/* ── CHECKDATASIG_SIGOPS parity enforcement (DEFAULT-OFF) ───────────────
 * zclassicd ConnectBlock (zclassic-cpp/src/main.cpp:2567) builds its script
 * verification flags as
 *   SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
 *   SCRIPT_VERIFY_CHECKDATASIG_SIGOPS.
 * The CHECKDATASIG_SIGOPS bit makes OP_CHECKDATASIG / OP_CHECKDATASIGVERIFY
 * count toward the per-block sigop total (script.c:117), so it tightens the
 * MAX_BLOCK_SIGOPS ceiling. connect_block.c below omits that bit. When this
 * flag is true, connect_block ORs it into the verification flags, matching
 * zclassicd exactly.
 *
 * Default false ⇒ connect_block's flags are byte-identical to today
 * (P2SH | CHECKLOCKTIMEVERIFY only), so the sigop accounting is unchanged.
 * Setting this bit can only RAISE a block's counted sigop total, so enabling
 * it is a tightening (reject) predicate: a real block that was previously
 * under the cap could now exceed it. It MUST stay default-off until a
 * FULL-HISTORY REPLAY against the real chain confirms ZERO false-rejects
 * first (h=478544 lesson — CLAUDE.md "validate against the CHAIN, not the
 * reference text"). zclassicd already applied this bit when it mined and
 * connected the chain, so the real history should never exceed the cap with
 * it on — but that must be PROVEN by replay before flipping the default or
 * passing the flag on the live node.
 *
 * Set by the node from the -enforce-checkdatasig-sigops argv flag
 * (src/main.c). _Atomic so a background validation thread reads it lock-free.
 * Note: connect_block.c is the boot-reindex path; the live reducer fold does
 * its own sigop accounting and is unaffected by this flag. */
_Atomic _Bool g_enforce_checkdatasig_sigops = false;

/* PURE recompute predicate — no DB, no globals, no input mutation.
 * Copies the pre-block frontier by value (incremental_merkle_tree is POD:
 * inline arrays + static function pointers, so a value-copy is a true deep
 * copy), appends this block's Sapling output commitments in order, folds
 * the root, and compares it to the header's hashFinalSaplingRoot.
 * NULL frontier ⇒ cannot-decide ⇒ return true (never false-reject). */
_Bool sapling_root_matches(const struct block *block,
                           const struct incremental_merkle_tree *pre_block_tree)
{
    if (!block || !pre_block_tree)
        return true; /* cannot recompute without a frontier; do not reject */

    struct incremental_merkle_tree t = *pre_block_tree; /* value copy */
    for (size_t i = 0; i < block->num_vtx; i++) {
        const struct transaction *tx = &block->vtx[i];
        for (size_t j = 0; j < tx->num_shielded_output; j++)
            incremental_tree_append(&t, &tx->v_shielded_output[j].cm);
    }

    struct uint256 recomputed;
    incremental_tree_root(&t, &recomputed);
    return memcmp(recomputed.data,
                  block->header.hashFinalSaplingRoot.data, 32) == 0;
}

#ifndef COINBASE_MATURITY
#define COINBASE_MATURITY 100
#endif
#include "script/interpreter.h"
#include <string.h>
#include "util/safe_alloc.h"

static bool checkpoint_covers(const struct checkpoint_data *cpdata,
                              int height)
{
    if (cpdata->nEntries <= 0)
        return false;
    return cpdata->entries[cpdata->nEntries - 1].height >= height;
}

bool connect_block(const struct block *block,
                   struct validation_state *state,
                   struct block_index *pindex,
                   struct coins_view_cache *view,
                   const struct chain_params *params,
                   bool just_check)
{
    /* Use pre-computed hash from block_index. */
    struct uint256 block_hash;
    if (pindex->phashBlock)
        block_hash = *pindex->phashBlock;
    else
        block_header_get_hash(&block->header, &block_hash);

    bool expensive_checks = true;
    if (checkpoint_covers(&params->checkpointData, pindex->nHeight))
        expensive_checks = false;
    if (g_deferred_proof_validation_below_height >= 0 && pindex->nHeight <= g_deferred_proof_validation_below_height)
        expensive_checks = false;

    /* Re-validate block. Merkle root is always checked (cheap SHA256d
     * over txids — catches data corruption even below deferred proof validation).
     * PoW and size limits gated by expensive_checks. */
    if (!check_block(block, state, params, expensive_checks,
                     !just_check, true)) {
        LOG_FAIL("connect", "check_block failed at height %d",
                 pindex->nHeight);
    }

    /* Genesis block: just set best block, no validation needed */
    if (uint256_cmp(&block_hash, &params->consensus.hashGenesisBlock) == 0) {
        if (!just_check) {
            /* Low-level: bypasses csr — `view` here is a stack-local
             * scratchpad (see process_block.c:817) that wraps coins_tip
             * as backing. The real tip commit runs in
             * process_block_commit_tip() → csr_commit_tip() after the flush
             * policy propagates this view to the global coins_tip. There is
             * no block_map / active_chain
             * mutation here; this is a single-field write inside an
             * in-flight block apply. */
            coins_view_cache_set_best_block(view, &block_hash);
        }
        return true;
    }

    event_emitf(EV_BLOCK_CONNECT_START, 0,
                "height=%d ntx=%zu", pindex->nHeight, block->num_vtx);

    /* ── View/prevblock invariant (zclassicd main.cpp:2513) ── */
    {
        struct uint256 view_best;
        coins_view_cache_get_best_block(view, &view_best);
        if (!uint256_is_null(&view_best) &&
            uint256_cmp(&block->header.hashPrevBlock, &view_best) != 0) {
            char vhex[65], phex[65];
            uint256_get_hex(&view_best, vhex);
            uint256_get_hex(&block->header.hashPrevBlock, phex);
            fprintf(stderr, "connect_block: FATAL view/prevblock mismatch "  // obs-ok:helper-context-logged
                    "h=%d view=%s prev=%s\n", pindex->nHeight, vhex, phex);
            REJECT_FATAL(state, "connect_block-view-mismatch");
        }
    }

    /* ── ZIP-209: Turnstile enforcement ─────────────────────── *
     * Shielded value pools (Sprout and Sapling) must never go negative.
     * This matches zclassicd ConnectBlock lines 2537-2551.
     *
     * CRITICAL: nChainSproutValue/nChainSaplingValue use boost::optional
     * semantics in zclassicd. We mirror this with has_chain_*_value flags.
     * Only enforce the turnstile when the cumulative value is KNOWN —
     * i.e., when every ancestor block's per-block value was computed.
     * If the parent's chain value is unknown (imported from LevelDB where
     * these weren't tracked), skip the check. */
    if (pindex->pprev) {
        /* Compute per-block shielded value from transactions */
        int64_t sprout_value = 0;
        int64_t sapling_value = 0;
        for (size_t i = 0; i < block->num_vtx; i++) {
            const struct transaction *tx = &block->vtx[i];
            for (size_t j = 0; j < tx->num_joinsplit; j++) {
                sprout_value += tx->v_joinsplit[j].vpub_old;
                sprout_value -= tx->v_joinsplit[j].vpub_new;
            }
            sapling_value += tx->value_balance;
        }
        pindex->nSproutValue = sprout_value;
        pindex->has_sprout_value = true;
        pindex->nSaplingValue = sapling_value;

        /* Propagate cumulative chain values only when parent is known */
        if (pindex->pprev->has_chain_sprout_value) {
            pindex->nChainSproutValue =
                pindex->pprev->nChainSproutValue + sprout_value;
            pindex->has_chain_sprout_value = true;

            /* ZIP-209: Sprout pool can't go negative */
            if (pindex->nChainSproutValue < 0) {
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID,
                    "bad-txns-sprout-turnstile-violation", false, NULL);
            }
        }

        if (pindex->pprev->has_chain_sapling_value) {
            pindex->nChainSaplingValue =
                pindex->pprev->nChainSaplingValue + sapling_value;
            pindex->has_chain_sapling_value = true;

            /* ZIP-209: Sapling pool can't go negative */
            if (pindex->nChainSaplingValue < 0) {
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID,
                    "bad-txns-sapling-turnstile-violation", false, NULL);
            }
        }
    }

    /* ── BIP30: no overwriting unspent transactions ─────────── *
     * Skip below deferred proof validation: when re-connecting blocks on top of an
     * imported UTXO snapshot, the coinbase outputs already exist in the
     * UTXO set. These blocks were validated by zclassicd — BIP30 is
     * redundant and would false-positive on the imported coinbases. */
    bool skip_bip30 = (g_deferred_proof_validation_below_height >= 0 &&
                       pindex->nHeight <= g_deferred_proof_validation_below_height);
    for (size_t i = 0; !skip_bip30 && i < block->num_vtx; i++) {
        if (coins_view_cache_have_coins(view, &block->vtx[i].hash)) {
            struct coins existing;
            coins_init(&existing);
            if (coins_view_cache_get_coins(view, &block->vtx[i].hash,
                                           &existing)) {
                if (!coins_is_pruned(&existing)) {
                    /* Self-write tolerance: when the existing unspent
                     * coin for one of THIS block's own transactions was
                     * created at THIS exact height, it is the residue of
                     * a prior partial apply of the same block (the UTXO
                     * set landed at H+1 while the tip cursor rewound to
                     * H — see BOOT_INVARIANTS.md "at-tip kill-9 ordering"
                     * and the BIP30 self-write wedge). connect_block is
                     * re-connecting the very block whose outputs are
                     * already present.
                     *
                     * This is NOT a real BIP30 violation: BIP30 forbids a
                     * DIFFERENT block from overwriting another block's
                     * still-unspent coinbase. A genuine duplicate would
                     * carry an existing coin from a DIFFERENT (earlier)
                     * height. Post-BIP34 every coinbase embeds its own
                     * height, so duplicate txids across distinct heights
                     * cannot occur — `existing.height == pindex->nHeight`
                     * uniquely identifies "the block's own prior write".
                     *
                     * Tolerating it lets the validator overwrite the
                     * stale coins with the freshly-validated ones and
                     * advance the tip; the full script/proof validation
                     * below still runs. Without this, a personal-stack
                     * node that took a kill-9 mid-connect wedges forever
                     * on its own coins. A partial apply can leave the
                     * block's NON-coinbase outputs in the set too, so
                     * every same-height self-write is tolerated, coinbase
                     * and non-coinbase alike. */
                    bool own_self_write =
                        existing.height == pindex->nHeight &&
                        pindex->nHeight > 0;
                    if (own_self_write) {
                        char txid[65];
                        uint256_get_hex(&block->vtx[i].hash, txid);
                        fprintf(stderr, // obs-ok:bip30-self-write-heal
                                "connect_block: tolerating same-height "
                                "self-write h=%d vtx=%zu txid=%s "
                                "coinbase=%d (stale local UTXO from prior "
                                "partial apply, BIP34 height-unique)\n",
                                pindex->nHeight, i, txid,
                                (int)existing.is_coinbase);
                        coins_free(&existing);
                        continue;
                    }
                    coins_free(&existing);
                    return validation_state_dos(state, 100, false,
                        REJECT_INVALID, "bad-txns-BIP30", false, NULL);
                }
            }
            coins_free(&existing);
        }
    }

    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    /* DEFAULT-OFF parity (-enforce-checkdatasig-sigops). zclassicd ORs
     * SCRIPT_VERIFY_CHECKDATASIG_SIGOPS into ConnectBlock's flags
     * (main.cpp:2567), which counts OP_CHECKDATASIG[VERIFY] toward the
     * per-block sigop ceiling. Default false ⇒ flags unchanged from today.
     * Enabling this tightening bit requires a full-history replay confirming
     * ZERO false-rejects first (see g_enforce_checkdatasig_sigops above). */
    if (atomic_load_explicit(&g_enforce_checkdatasig_sigops,
                             memory_order_relaxed))
        flags |= SCRIPT_VERIFY_CHECKDATASIG_SIGOPS;

    struct block_undo blockundo;
    block_undo_init(&blockundo);
    if (block->num_vtx > 1) {
        if (!block_undo_alloc(&blockundo, block->num_vtx - 1)) {
            block_undo_free(&blockundo);
            LOG_FAIL("connect", "block_undo_alloc failed at height %d ntx=%zu",
                     pindex->nHeight, block->num_vtx);
        }
    }

    uint32_t branch_id = consensus_current_epoch_branch_id(
        pindex->nHeight, &params->consensus);

    int64_t fees = 0;
    unsigned int sig_ops = 0;

    /* ── Parallel script verification: collection arrays ─── *
     * Phase 1 (in the loop below): gather all script checks.
     * Phase 2 (after the loop): dispatch to workpool.
     * txdatas[] holds precomputed tx data that outlives the loop.
     *
     * SAFETY: `check_ptrs[i]` points into `checks[]`, and each
     * `sc->txdata` points into `txdatas[]`.  If either array is
     * reallocated to a new base address while collection is still
     * running, ALL previously recorded pointers become dangling.
     * Worker threads later dereference them → SEGV. A block with
     * enough inputs to grow the array past its initial cap (e.g. two
     * 200-input txs) triggers a realloc mid-collection that strands
     * every earlier pointer; workpool_run then crashes.
     *
     * Fix: pre-scan the block once to get exact upper bounds on
     * num_checks and num_txdatas, then allocate those sizes up
     * front.  No realloc during collection, no dangling pointers. */
    size_t checks_cap = 0;
    size_t txdatas_cap = 0;
    for (size_t pi = 0; pi < block->num_vtx; pi++) {
        const struct transaction *ptx = &block->vtx[pi];
        if (transaction_is_coinbase(ptx))
            continue;
        txdatas_cap++;
        checks_cap += ptx->num_vin;
    }
    /* Defensive: at least one slot so NULL-alloc branches
     * stay simple; bump cap if caller wants extra. */
    if (checks_cap == 0) checks_cap = 1;
    if (txdatas_cap == 0) txdatas_cap = 1;

    struct script_check *checks =
        zcl_malloc(checks_cap * sizeof(*checks), "connect_checks");
    void **check_ptrs =
        zcl_malloc(checks_cap * sizeof(*check_ptrs), "connect_check_ptrs");
    struct precomputed_tx_data *txdatas =
        zcl_malloc(txdatas_cap * sizeof(*txdatas), "connect_txdatas");
    if (!checks || !check_ptrs || !txdatas) {
        free(checks);
        free(check_ptrs);
        free(txdatas);
        block_undo_free(&blockundo);
        REJECT_FATAL(state, "out-of-memory");
    }
    size_t num_checks = 0;
    size_t num_txdatas = 0;

    for (size_t i = 0; i < block->num_vtx; i++) {
        const struct transaction *tx = &block->vtx[i];

        /* ── Sigops check ─────────────────────────────── */
        sig_ops += (unsigned int)get_legacy_sig_op_count(tx, flags);
        if (sig_ops > MAX_BLOCK_SIGOPS) {
            free(checks); free(check_ptrs); free(txdatas);
            block_undo_free(&blockundo);
            return validation_state_dos(state, 100, false,
                REJECT_INVALID, "bad-blk-sigops", false, NULL);
        }

        if (!transaction_is_coinbase(tx)) {
            /* ── Coinbase maturity (100 blocks) ───────── */
            for (size_t j = 0; j < tx->num_vin; j++) {
                struct coins prev_coins;
                coins_init(&prev_coins);
                if (coins_view_cache_get_coins(view,
                        &tx->vin[j].prevout.hash, &prev_coins)) {
                    if (prev_coins.is_coinbase &&
                        pindex->nHeight - prev_coins.height < COINBASE_MATURITY) {
                        coins_free(&prev_coins);
                        free(checks); free(check_ptrs); free(txdatas);
                        block_undo_free(&blockundo);
                        return validation_state_dos(state, 100, false,
                            REJECT_INVALID,
                            "bad-txns-premature-spend-of-coinbase",
                            false, NULL);
                    }
                }
                coins_free(&prev_coins);
            }

            /* ── All inputs must exist and be unspent ── */
            if (!coins_view_cache_have_inputs(view, tx)) {
                /* The missing input is identified + repaired by the reducer
                 * prevout_unresolved path (app/jobs/script_validate_stage.c),
                 * not here — connect_block just rejects. Emit a structured
                 * reject so consensus_reject_index can answer "why?". */
                char bhex[65];
                uint256_get_hex(&block_hash, bhex);
                event_emitf(EV_CONSENSUS_REJECT_BLOCK, 0,
                            "hash=%s reason=bad-txns-inputs-missingorspent "
                            "dos=100", bhex);
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false, REJECT_INVALID,
                    "bad-txns-inputs-missingorspent", false, NULL);
            }

            /* ── JoinSplit anchor requirements ─────────── */
            if (!coins_view_cache_have_joinsplit_requirements(view, tx)) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID,
                    "bad-txns-joinsplit-requirements-not-met", false,
                    NULL);
            }

            /* ── P2SH sigops ────────────────────── *
             * Add sigops done by pay-to-script-hash inputs; prevents a
             * rogue miner from hiding an expensive-to-validate block
             * inside a small scriptSig.  Mirrors zclassicd
             * src/main.cpp::GetP2SHSigOpCount + the ConnectBlock check
             * at main.cpp:2634-2637.  Must run AFTER have_inputs so the
             * prevouts are guaranteed to be in the view cache. */
            sig_ops += (unsigned int)get_p2sh_sig_op_count(tx, view, flags);
            if (sig_ops > MAX_BLOCK_SIGOPS) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-blk-sigops", false, NULL);
            }
        }

        /* ── Fee calculation with per-input MoneyRange ─── */
        if (!transaction_is_coinbase(tx)) {
            int64_t value_in = coins_view_cache_get_value_in(view, tx);
            int64_t value_out = transaction_get_value_out(tx);

            /* get_value_in returns -1 on missing inputs or out-of-range values.
             * This catches corrupted coins before they propagate. */
            if (value_in < 0) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-txns-inputvalues-outofrange",
                    false, NULL);
            }

            /* Per-input value range check (zclassicd CheckTxInputs:2075) */
            if (!MoneyRange(value_in)) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-txns-inputvalues-outofrange",
                    false, NULL);
            }

            /* Inputs must cover outputs (no money creation) */
            if (value_in < value_out) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-txns-in-belowout", false, NULL);
            }

            int64_t tx_fee = value_in - value_out;

            /* Fee sanity: non-negative and no overflow */
            if (tx_fee < 0) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-txns-fee-negative", false, NULL);
            }
            if (!MoneyRange(fees + tx_fee)) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-txns-fee-outofrange", false, NULL);
            }
            fees += tx_fee;

            event_emitf(EV_TX_INPUTS_CHECKED, 0,
                        "h=%d tx=%zu value_in=%lld fee=%lld",
                        pindex->nHeight, i,
                        (long long)value_in, (long long)tx_fee);

            /* ── Script verification (Phase 1: collect) ─── */
            if (expensive_checks) {
                if (num_txdatas >= txdatas_cap) {
                    txdatas_cap = txdatas_cap ? txdatas_cap * 2 : 64;
                    struct precomputed_tx_data *nt = zcl_realloc(txdatas,
                                      txdatas_cap * sizeof(*txdatas), "connect_txdatas");
                    if (!nt) {
                        free(checks);
                        free(check_ptrs);
                        free(txdatas);
                        block_undo_free(&blockundo);
                        REJECT_FATAL(state, "out-of-memory");
                    }
                    txdatas = nt;
                }
                precompute_tx_data(tx, &txdatas[num_txdatas]);
                num_txdatas++;

                for (size_t j = 0; j < tx->num_vin; j++) {
                    const struct tx_out *prev_out =
                        coins_view_cache_get_output_for(view, &tx->vin[j]);
                    if (!prev_out) {
                        free(checks);
                        free(check_ptrs);
                        free(txdatas);
                        block_undo_free(&blockundo);
                        return validation_state_dos(state, 100, false,
                            REJECT_INVALID, "bad-txns-inputs-missingorspent",
                            false, NULL);
                    }

                    /* Per-input value in valid range */
                    if (!MoneyRange(prev_out->value)) {
                        free(checks);
                        free(check_ptrs);
                        free(txdatas);
                        block_undo_free(&blockundo);
                        return validation_state_dos(state, 100, false,
                            REJECT_INVALID,
                            "bad-txns-inputvalues-outofrange",
                            false, NULL);
                    }

                    if (num_checks >= checks_cap) {
                        checks_cap = checks_cap ? checks_cap * 2 : 256;
                        struct script_check *nc = zcl_realloc(checks,
                                         checks_cap * sizeof(*checks), "connect_checks");
                        void **np = zcl_realloc(check_ptrs,
                                             checks_cap * sizeof(*check_ptrs), "connect_check_ptrs");
                        if (!nc || !np) {
                            free(nc ? nc : checks);
                            free(np ? np : check_ptrs);
                            free(txdatas);
                            block_undo_free(&blockundo);
                            REJECT_FATAL(state, "out-of-memory");
                        }
                        checks = nc;
                        check_ptrs = np;
                    }

                    struct script_check *sc = &checks[num_checks];
                    sc->script_sig = &tx->vin[j].script_sig;
                    sc->script_pub_key = &prev_out->script_pub_key;
                    sc->flags = flags;
                    sc->branch_id = branch_id;
                    sc->txdata = &txdatas[num_txdatas - 1];
                    tx_sig_checker_init(&sc->tsc, tx, (unsigned int)j,
                                        prev_out->value, branch_id,
                                        sc->txdata);
                    check_ptrs[num_checks] = sc;
                    num_checks++;
                }
            }
        }

        /* ── Update UTXO set ──────────────────────────── */
        if (i > 0) {
            if (!update_coins_with_undo(tx, view, &blockundo.vtxundo[i - 1],
                                        pindex->nHeight)) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false, REJECT_INVALID,
                    "bad-txns-utxo-update-failed", true, NULL);
            }
        } else {
            struct tx_undo dummy;
            tx_undo_init(&dummy);
            bool ok = update_coins_with_undo(tx, view, &dummy,
                                              pindex->nHeight);
            tx_undo_free(&dummy);
            if (!ok) {
                free(checks); free(check_ptrs); free(txdatas);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false, REJECT_INVALID,
                    "bad-txns-utxo-update-failed", true, NULL);
            }
        }
    }

    /* ── Script verification (Phase 2: parallel dispatch) ─── *
     * All inputs have been collected into checks[]. Now verify them
     * in parallel via the workpool. UTXO updates above are already
     * complete, so the coins view is not accessed by workers. */
    if (num_checks > 0) {
        struct workpool *pool = get_script_pool();
        bool scripts_ok;

        if (pool && num_checks >= 4) {
            /* Parallel path: dispatch to worker threads */
            scripts_ok = workpool_run(pool, check_ptrs, num_checks);
        } else {
            /* Sequential fallback: < 4 inputs or pool init failed */
            scripts_ok = true;
            for (size_t c = 0; c < num_checks && scripts_ok; c++)
                scripts_ok = script_check_fn(check_ptrs[c]);
        }

        free(checks);
        free(check_ptrs);
        free(txdatas);

        if (!scripts_ok) {
            block_undo_free(&blockundo);
            return validation_state_dos(state, 100, false,
                REJECT_INVALID, "mandatory-script-verify-flag-failed",
                false, NULL);
        }

        event_emitf(EV_SCRIPT_VERIFIED, 0,
                    "h=%d inputs=%zu parallel=%s",
                    pindex->nHeight, num_checks,
                    (pool && num_checks >= 4) ? "yes" : "no");
    } else {
        free(checks);
        free(check_ptrs);
        free(txdatas);
    }

    /* ── Sapling commitment tree root verification ─────────── *
     * The Sapling tree is maintained by sync_controller which handles
     * both tree updates AND wallet witness advancement. It verifies
     * hashFinalSaplingRoot matches the computed tree root after each
     * block. See sync_controller.c:291-325.
     *
     * connect_block validates the tree root was set correctly in the
     * block header by checking it's not all-zeros after Sapling activation
     * (a basic sanity check — full verification is in sync_controller). */
    if (!just_check) {
        bool sapling_active = consensus_network_upgrade_active(
            &params->consensus, pindex->nHeight, UPGRADE_SAPLING);
        if (sapling_active) {
            static const uint8_t zeros[32] = {0};
            if (memcmp(block->header.hashFinalSaplingRoot.data, zeros, 32) == 0) {
                fprintf(stderr, "connect_block: hashFinalSaplingRoot is "  // obs-ok:helper-context-logged
                        "all-zeros at Sapling height %d\n", pindex->nHeight);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-sapling-root-zeroed", false,
                    NULL);
            }

            /* DEFAULT-OFF full parity reject. Only runs when the operator
             * has enabled -enforce-sapling-root (default false), so default
             * behavior above is byte-identical to today (zeros-only reject).
             * Recompute is PURE: sapling_root_matches folds a value-copy of
             * the pre-block frontier; with no frontier wired (g_sapling_tree
             * NULL) it returns true and cannot false-reject. Enabling this
             * requires a full-history replay (0 false-rejects) FIRST — see
             * the h=478544 lesson in connect_block.h. */
            if (atomic_load_explicit(&g_enforce_sapling_root,
                                     memory_order_relaxed) &&
                !sapling_root_matches(block, g_sapling_tree)) {
                fprintf(stderr, "connect_block: hashFinalSaplingRoot "  // obs-ok:helper-context-logged
                        "mismatch at Sapling height %d "
                        "(-enforce-sapling-root)\n", pindex->nHeight);
                block_undo_free(&blockundo);
                return validation_state_dos(state, 100, false,
                    REJECT_INVALID, "bad-sapling-root-mismatch", false,
                    NULL);
            }
        }
    }

    /* ── Coinbase reward validation ───────────────────────── */
    int64_t subsidy = get_block_subsidy(pindex->nHeight, &params->consensus);
    if (fees > INT64_MAX - subsidy) {
        block_undo_free(&blockundo);
        return validation_state_dos(state, 100, false, REJECT_INVALID,
            "bad-cb-reward-overflow", false, NULL);
    }

    int64_t block_reward = fees + subsidy;
    if (transaction_get_value_out(&block->vtx[0]) > block_reward) {
        block_undo_free(&blockundo);
        return validation_state_dos(state, 100, false, REJECT_INVALID,
            "bad-cb-amount", false, NULL);
    }

    if (just_check) {
        block_undo_free(&blockundo);
        return true;
    }

    /* Low-level: bypasses csr — `view` is a stack-local scratchpad
     * (process_block.c:817) wrapping coins_tip as backing. The real
     * tip commit happens in update_tip() → process_block_commit_tip()
     * → csr_commit_tip() after the flush policy promotes this view's
     * pending writes to the global coins_tip. */
    coins_view_cache_set_best_block(view, &block_hash);

    event_emitf(EV_BLOCK_CONNECT_DONE, 0,
                "height=%d fees=%lld sigops=%u",
                pindex->nHeight, (long long)fees, sig_ops);

    block_undo_free(&blockundo);
    return true;
}

bool disconnect_block(const struct block *block,
                      struct validation_state *state,
                      struct block_index *pindex,
                      struct coins_view_cache *view,
                      const struct block_undo *blockundo)
{
    (void)state;

    if (blockundo->num_txundo != block->num_vtx - 1) {
        fprintf(stderr, "disconnect_block: undo size mismatch "
                "(undo=%zu vtx=%zu)\n",
                blockundo->num_txundo, block->num_vtx);
        return false;
    }

    for (size_t i = block->num_vtx; i-- > 0; ) {
        const struct transaction *tx = &block->vtx[i];

        if (i > 0) {
            const struct tx_undo *txundo = &blockundo->vtxundo[i - 1];
            if (txundo->num_prevout != tx->num_vin) {
                fprintf(stderr, "disconnect_block: txundo prevout mismatch "
                        "tx=%zu (prevout=%zu vin=%zu)\n",
                        i, txundo->num_prevout, tx->num_vin);
                return false;
            }

            for (size_t j = tx->num_vin; j-- > 0; ) {
                const struct tx_in_undo *undo = &txundo->vprevout[j];
                struct coins_cache_entry *entry =
                    coins_view_cache_modify(view, &tx->vin[j].prevout.hash);
                if (!entry) {
                    fprintf(stderr, "disconnect_block: coins_modify failed "
                            "tx=%zu vin=%zu\n", i, j);
                    return false;
                }

                if (tx->vin[j].prevout.n >= entry->coins.num_vout) {
                    size_t old_size = entry->coins.num_vout;
                    /* Clamp prevout.n against MAX_BLOCK_SIZE before
                     * extending the vout array. A valid funding tx
                     * cannot encode more than MAX_BLOCK_SIZE / ~30
                     * outputs (each tx_out is at least 8-byte value +
                     * minimal scriptPubKey), so anything beyond that
                     * ceiling is either corrupted block data or an
                     * attacker-controlled value crafted to force a
                     * ~128 GB realloc (prevout.n = UINT32_MAX =>
                     * 2**32 * sizeof(tx_out) ≈ 128 GB). */
                    if (tx->vin[j].prevout.n >= MAX_BLOCK_SIZE) {
                        LOG_FAIL("disconnect",
                                 "prevout.n out of range h=%d tx=%zu vin=%zu n=%u",
                                 pindex->nHeight, i, j, tx->vin[j].prevout.n);
                    }
                    size_t new_size = tx->vin[j].prevout.n + 1;
                    struct tx_out *new_vout =
                        zcl_realloc(entry->coins.vout,
                                new_size * sizeof(struct tx_out), "disconnect_vout");
                    if (!new_vout) {
                        fprintf(stderr, "disconnect_block: realloc failed "
                                "tx=%zu vin=%zu new_size=%zu\n", i, j, new_size);
                        return false;
                    }
                    for (size_t k = entry->coins.num_vout; k < new_size; k++)
                        tx_out_set_null(&new_vout[k]);
                    entry->coins.vout = new_vout;
                    entry->coins.num_vout = new_size;
                    coins_view_cache_account_vout_resize(
                        view, old_size, new_size);
                }

                if (undo->height > 0) {
                    entry->coins.is_coinbase = undo->coinbase;
                    entry->coins.height = (int)undo->height;
                    entry->coins.version = undo->version;
                }
                entry->coins.vout[tx->vin[j].prevout.n] = undo->txout;
                entry->flags |= COINS_CACHE_DIRTY;
            }
        }

        /* Remove this tx's outputs from the coins view.
         *
         * The scratch view wrapping coins_tip is populated lazily by
         * coins_view_cache_modify / get_coins, and cvc_batch_write
         * (lib/coins/src/coins_view.c:255) only propagates DIRTY
         * entries to the backing store — the same rule holds for the
         * SQLite flush at coins_view_sqlite.c:664. A bare
         * `coins_map_erase` on the scratch is therefore a no-op with
         * respect to the backing: the tx's outputs survive in
         * coins_tip, and (after the next flush) in SQLite's utxos
         * table, even though the block creating them has been
         * disconnected. Any subsequent reconnect of the same block
         * trips BIP30 on the have_coins fall-through.
         *
         * Fix: materialize the backing entry into the scratch as a
         * DIRTY+pruned tombstone so cvc_batch_write propagates a
         * pruned entry to the parent (which in turn drives the
         * DELETE at coins_view_sqlite.c:667 on the next coins flush).
         * Matches Bitcoin Core's CCoinsViewCache semantics (erase
         * semantics propagate through LevelDB's CDBBatch::Erase),
         * while staying compatible with our DIRTY-driven SQLite
         * flush path.
         *
         * `coins_view_cache_modify` fetches the backing entry into
         * the scratch on miss; freeing the coins + re-init'ing makes
         * coins_is_pruned return true, so cvc_batch_write takes the
         * pruned branch and the DELETE signal reaches the backing. */
        struct coins_cache_entry *ghost =
            coins_view_cache_modify(view, &tx->hash);
        if (ghost) {
            coins_free(&ghost->coins);
            coins_init(&ghost->coins);
            ghost->flags |= COINS_CACHE_DIRTY;
        }
    }

    if (pindex->pprev && pindex->pprev->phashBlock) {
        /* Low-level: bypasses csr — `view` is the stack-local rollback
         * scratchpad. The global tip commit happens after the reducer unwind
         * path propagates this view to coins_tip and publishes through
         * process_block_commit_tip() → csr_commit_tip(). */
        coins_view_cache_set_best_block(view, pindex->pprev->phashBlock);
    }

    return true;
}
