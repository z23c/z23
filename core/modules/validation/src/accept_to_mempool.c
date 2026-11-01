/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * accept_to_mempool — the ONE shared mempool-acceptance gate used by
 * both the P2P `tx` handler and the RPC sendrawtransaction handler.
 * See validation/accept_to_mempool.h for the contract and the bug this
 * closes (unverified-sig / unverified-proof txs being relayed). */

#include "validation/accept_to_mempool.h"
#include "validation/check_transaction.h"
#include "validation/contextual_check_tx.h"
#include "validation/txmempool.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "coins/coins_view.h"
#include "chain/chainparams.h"
#include "script/interpreter.h"
#include "script/script_flags.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdatomic.h>

static _Atomic(const struct mempool_backend_guard *) g_backend_guard;

bool mempool_install_backend_guard(const struct mempool_backend_guard *guard)
{
    if (!guard || !guard->acquire || !guard->release) return false;
    const struct mempool_backend_guard *expected = NULL;
    return atomic_compare_exchange_strong(&g_backend_guard, &expected, guard) ||
           expected == guard;
}

static const struct mempool_backend_guard *mempool_guard_enter(
    struct main_state *state)
{
    const struct mempool_backend_guard *guard = atomic_load(&g_backend_guard);
    if (!guard) {
        zcl_mutex_lock(&state->cs_main);
        return NULL;
    }
    for (;;) {
        guard->acquire();
        if (zcl_mutex_trylock(&state->cs_main)) return guard;
        guard->release();
        platform_sleep_ms(1);
    }
}

static void mempool_guard_leave(struct main_state *state,
                                const struct mempool_backend_guard *guard)
{
    zcl_mutex_unlock(&state->cs_main);
    if (guard) guard->release();
}

static void mempool_accept_detail(char *out, size_t cap, const char *detail)
{
    if (out && cap > 0)
        (void)snprintf(out, cap, "%s", detail && detail[0] ? detail : "invalid");
}

/* Verify every transparent input's scriptSig against its prevout's
 * scriptPubKey. Mirrors the per-input check in connect_block.c exactly
 * (same flags, same branch id, same precomputed sighash data) so a tx
 * that passes here would also pass connect_block — and one that fails
 * here is one connect_block would have rejected too. Runs serially
 * (mempool txs are single, not whole blocks; the parallel workpool is
 * connect_block's optimisation for big blocks).
 *
 * Returns true iff all inputs verify. On a missing prevout returns
 * false via *missing_inputs (orphan, not a malicious script failure). */
static bool verify_tx_inputs_scripts(struct coins_view_cache *view,
                                     const struct transaction *tx,
                                     uint32_t branch_id,
                                     bool *missing_inputs)
{
    *missing_inputs = false;

    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

    struct precomputed_tx_data txdata;
    precompute_tx_data(tx, &txdata);

    for (size_t j = 0; j < tx->num_vin; j++) {
        const struct tx_out *prev_out =
            coins_view_cache_get_output_for(view, &tx->vin[j]);
        if (!prev_out) {
            /* Should not happen — caller already ran have_inputs — but
             * stay defensive: treat as orphan rather than a script
             * failure so an honest race doesn't earn a ban-score. */
            *missing_inputs = true;
            return false;
        }

        struct tx_sig_checker tsc;
        tx_sig_checker_init(&tsc, tx, (unsigned int)j, prev_out->value,
                            branch_id, &txdata);
        struct sig_checker checker = tx_make_sig_checker(&tsc);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!verify_script(&tx->vin[j].script_sig,
                           &prev_out->script_pub_key,
                           flags, &checker, branch_id, &serror)) {
            return false;
        }
    }
    return true;
}

/* When detail_out has room, write an empty string, then reject bad
 * arguments, a standalone coinbase, or a structural failure. */
static enum mempool_accept_result mempool_accept_context_free(
    struct tx_mempool *pool,
    const struct transaction *tx,
    char *detail_out,
    size_t detail_cap)
{
    if (detail_out && detail_cap > 0)
        detail_out[0] = '\0';
    if (!pool || !tx)
        return MEMPOOL_ACCEPT_INTERNAL_ERROR;

    /* Coinbase txs are only valid as the first tx of a block; they must
     * never be relayed standalone. */
    if (transaction_is_coinbase(tx)) {
        mempool_accept_detail(detail_out, detail_cap, "coinbase-standalone");
        return MEMPOOL_ACCEPT_INVALID;
    }

    /* 1. Structural / context-free checks. STANDALONE context on
     * purpose: a NEW tx always gets the strict post-Sapling 102000 size
     * cap regardless of history — the empirical oversize grandfather is
     * in-block only, matching zclassicd's AcceptToMemoryPool ->
     * CheckTransaction, which is always strict. */
    struct validation_state state;
    validation_state_init(&state);
    if (!check_transaction(tx, &state)) {
        mempool_accept_detail(detail_out, detail_cap, state.reject_reason);
        return MEMPOOL_ACCEPT_INVALID;
    }
    return MEMPOOL_ACCEPT_OK;
}

/* Store tip height and the lock-time cutoff, using the tip median-time-past
 * when a tip exists. */
static void mempool_accept_snapshot_tip(struct main_state *main_state,
                                        int *tip_height,
                                        int64_t *lock_time_cutoff)
{
    *tip_height = 0;
    *lock_time_cutoff = (int64_t)platform_time_wall_time_t();
    /* BIP113 mempool policy evaluates against the current tip's MTP.
     * Snapshot height + cutoff under cs_main so a concurrent reorg cannot
     * give us a height from one tip and a timestamp from another. */
    const struct mempool_backend_guard *snapshot_guard =
        mempool_guard_enter(main_state);
    *tip_height = active_chain_height(&main_state->chain_active);
    struct block_index *tip = active_chain_tip(&main_state->chain_active);
    if (tip)
        *lock_time_cutoff = block_index_get_median_time_past(tip);
    mempool_guard_leave(main_state, snapshot_guard);
}

/* Return the accept result for the shielded contextual-check verdict. */
static enum mempool_accept_result mempool_accept_shielded(
    const struct transaction *tx,
    const struct chain_params *params,
    int next_height,
    char *detail_out,
    size_t detail_cap)
{
    /* 2. Height-aware shielded checks: JoinSplit Ed25519 signature,
     *    Sapling Groth16 spend/output proofs + binding signature, and
     *    Sprout zk-SNARK proofs. THIS is the proof verification the
     *    relay path was missing. dosLevel 100 mirrors the relay-time
     *    contextual check in zclassicd's AcceptToMemoryPool. */
    struct validation_state state;
    validation_state_init(&state);
    switch (contextual_check_transaction_verdict(tx, &state,
                                                 &params->consensus,
                                                 next_height, 100)) {
    case CONTEXTUAL_CHECK_PASS:
        break;
    case CONTEXTUAL_CHECK_UNVERIFIABLE:
        /* We hold no verdict on this transaction — we could not form one.
         * Reject it (never relay an unverified shielded tx) but report the
         * distinct result so the caller does not blame the sender for our
         * own missing keys / failed allocation. */
        mempool_accept_detail(detail_out, detail_cap, state.reject_reason);
        return MEMPOOL_ACCEPT_UNVERIFIABLE;
    case CONTEXTUAL_CHECK_REJECT:
        mempool_accept_detail(detail_out, detail_cap, state.reject_reason);
        return MEMPOOL_ACCEPT_INVALID;
    }
    return MEMPOOL_ACCEPT_OK;
}

/* Reject absent inputs, absent shielded requirements, a negative value, an
 * unbalanced value, or a low relay fee, and store the fee. */
static enum mempool_accept_result mempool_accept_inputs_and_fee(
    struct tx_mempool *pool,
    struct coins_view_cache *coins_tip,
    const struct transaction *tx,
    char *detail_out,
    size_t detail_cap,
    int64_t *fee_out)
{
    *fee_out = 0;
    if (!coins_view_cache_have_inputs(coins_tip, tx))
        return MEMPOOL_ACCEPT_MISSING_INPUTS;
    if (!coins_view_cache_have_joinsplit_requirements(coins_tip, tx)) {
        mempool_accept_detail(detail_out, detail_cap,
                              "shielded-requirements-missing");
        return MEMPOOL_ACCEPT_INVALID;
    }

    int64_t value_in = coins_view_cache_get_value_in(coins_tip, tx);
    if (value_in < 0) {
        mempool_accept_detail(detail_out, detail_cap, "input-value-invalid");
        return MEMPOOL_ACCEPT_INVALID;
    }

    int64_t value_out = transaction_get_value_out(tx);
    if (value_out < 0 || value_in < value_out) {
        mempool_accept_detail(detail_out, detail_cap, "value-balance-invalid");
        return MEMPOOL_ACCEPT_INVALID;
    }

    int64_t fee = value_in - value_out;
    *fee_out = fee;

    int64_t min_relay_fee = pool->min_relay_fee;
    if (min_relay_fee > 0 && fee < min_relay_fee)
        return MEMPOOL_ACCEPT_BELOW_FEE;
    return MEMPOOL_ACCEPT_OK;
}

/* Verify transparent input scripts and map failure to missing inputs or
 * invalid. */
static enum mempool_accept_result mempool_accept_transparent_scripts(
    struct coins_view_cache *coins_tip,
    const struct transaction *tx,
    uint32_t branch_id,
    char *detail_out,
    size_t detail_cap)
{
    /* Transparent scriptSig verification — a bad-sig tx is rejected here,
     * BEFORE add+relay. */
    bool missing_inputs = false;
    if (!verify_tx_inputs_scripts(coins_tip, tx, branch_id,
                                  &missing_inputs)) {
        if (!missing_inputs)
            mempool_accept_detail(detail_out, detail_cap,
                                  "transparent-script-invalid");
        return missing_inputs ? MEMPOOL_ACCEPT_MISSING_INPUTS
                              : MEMPOOL_ACCEPT_INVALID;
    }
    return MEMPOOL_ACCEPT_OK;
}

/* Add the transaction to the mempool and return duplicate or internal error
 * when it is not kept. */
static enum mempool_accept_result mempool_accept_insert(
    struct tx_mempool *pool,
    const struct transaction *tx,
    const struct uint256 *hash,
    int64_t fee,
    int next_height,
    uint32_t branch_id)
{
    struct mempool_entry entry;
    mempool_entry_init(&entry, tx, fee,
                       (int64_t)platform_time_wall_time_t(), 0.0,
                       (unsigned int)next_height,
                       tx_mempool_has_no_inputs_of(pool, tx),
                       false, branch_id);

    bool added = tx_mempool_add_unchecked(pool, hash, &entry);
    /* tx_mempool_add_unchecked deep-copies the entry. Always release this
     * staging copy; omitting the success-path free leaked one full transaction
     * per accepted relay and made sustained traffic an unbounded heap leak. */
    mempool_entry_free(&entry);
    if (!added) {
        /* A concurrent delivery of this exact immutable transaction may have
         * won the locked insertion after our optimistic exists probe. Report
         * the durable owner accurately; any other insertion failure remains
         * an internal error. */
        enum mempool_accept_result race_result = tx_mempool_exists(pool, hash)
            ? MEMPOOL_ACCEPT_DUPLICATE
            : MEMPOOL_ACCEPT_INTERNAL_ERROR;
        return race_result;
    }

    /* The post-add policy hook may evict synchronously after limits are
     * recomputed. Never report success/relay a candidate no longer owned by
     * the mempool. */
    if (!tx_mempool_exists(pool, hash))
        return MEMPOOL_ACCEPT_INTERNAL_ERROR;
    return MEMPOOL_ACCEPT_OK;
}

/* Take the backend guard, run input, script, and insertion checks, then
 * release it. */
static enum mempool_accept_result mempool_accept_under_guard(
    struct tx_mempool *pool,
    struct coins_view_cache *coins_tip,
    struct main_state *main_state,
    const struct transaction *tx,
    const struct uint256 *hash,
    int next_height,
    uint32_t branch_id,
    char *detail_out,
    size_t detail_cap)
{
    /* 3. Input-dependent checks. The transparent SIGNATURE check
     *    (verify_script) lives here because it needs each prevout's
     *    scriptPubKey + value from the view. */
    int64_t fee = 0;

    /* Serialize the input-dependent decision and final insertion with tip
     * publication. A second delivery can begin validation while this tx is
     * being mined; without this ownership boundary it may finish after the
     * finalized-block path removes the first copy and reinsert the now-
     * confirmed transaction using the pre-connect cache generation. If we
     * win the lock first, finalize removes our entry. If finalize wins, it
     * invalidates changed cache keys first and this recheck fails closed. */
    const struct mempool_backend_guard *guard = mempool_guard_enter(main_state);
    enum mempool_accept_result result = mempool_accept_inputs_and_fee(
        pool, coins_tip, tx, detail_out, detail_cap, &fee);
    if (result == MEMPOOL_ACCEPT_OK)
        result = mempool_accept_transparent_scripts(
            coins_tip, tx, branch_id, detail_out, detail_cap);
    if (result == MEMPOOL_ACCEPT_OK)
        result = mempool_accept_insert(pool, tx, hash, fee, next_height,
                                        branch_id);
    mempool_guard_leave(main_state, guard);
    return result;
}

enum mempool_accept_result accept_to_mempool_detailed(
    struct tx_mempool *pool,
    struct coins_view_cache *coins_tip,
    struct main_state *main_state,
    const struct chain_params *params,
    struct transaction *tx,
    char *detail_out,
    size_t detail_cap)
{
    enum mempool_accept_result result =
        mempool_accept_context_free(pool, tx, detail_out, detail_cap);
    if (result != MEMPOOL_ACCEPT_OK)
        return result;

    /* A live acceptance decision is impossible without all three chain
     * authorities. Historically NULL test scaffolding skipped proof, input,
     * fee, and script checks and then admitted the transaction anyway. Keep
     * structural-invalid classification above for diagnostics, but never add
     * a structurally-valid transaction through an incomplete context. */
    if (!coins_tip || !main_state || !params)
        return MEMPOOL_ACCEPT_INTERNAL_ERROR;

    transaction_compute_hash(tx);
    struct uint256 hash = tx->hash;

    if (tx_mempool_exists(pool, &hash))
        return MEMPOOL_ACCEPT_DUPLICATE;

    /* Double-spend vs current mempool — explicit probe so the caller
     * can attribute it to the sending peer. */
    if (tx_mempool_has_conflict(pool, tx))
        return MEMPOOL_ACCEPT_CONFLICT;

    int tip_height = 0;
    int64_t lock_time_cutoff = 0;
    mempool_accept_snapshot_tip(main_state, &tip_height, &lock_time_cutoff);
    int next_height = tip_height + 1;
    uint32_t branch_id =
        consensus_current_epoch_branch_id(next_height, &params->consensus);

    /* Match zclassicd CheckFinalTx: mempool transactions must already be
     * final for the next block, using tip median-time-past for time locks.
     * This is relay policy (block connection performs its own consensus
     * finality check against the candidate block time). */
    if (!is_final_tx(tx, next_height, lock_time_cutoff))
        return MEMPOOL_ACCEPT_NONFINAL;
    if (is_expiring_soon_tx(tx, next_height))
        return MEMPOOL_ACCEPT_EXPIRING_SOON;

    result = mempool_accept_shielded(tx, params, next_height,
                                     detail_out, detail_cap);
    if (result != MEMPOOL_ACCEPT_OK)
        return result;

    return mempool_accept_under_guard(pool, coins_tip, main_state, tx, &hash,
                                      next_height, branch_id,
                                      detail_out, detail_cap);
}

enum mempool_accept_result accept_to_mempool(
    struct tx_mempool *pool,
    struct coins_view_cache *coins_tip,
    struct main_state *main_state,
    const struct chain_params *params,
    struct transaction *tx)
{
    return accept_to_mempool_detailed(pool, coins_tip, main_state, params, tx,
                                      NULL, 0);
}
