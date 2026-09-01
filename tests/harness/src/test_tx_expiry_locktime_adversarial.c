/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Adversarial coverage of transaction expiry (nExpiryHeight / ZIP-203)
 * and nLockTime / final-tx rules AT the two places they are actually
 * enforced against live chain state: contextual_check_block() /
 * contextual_check_transaction() (block-connect) and accept_to_mempool()
 * (relay policy).
 *
 * test_domain_consensus_locktime.c and test_locktime_edge.c already pin the
 * PURE domain_consensus_tx_is_final / domain_consensus_tx_is_expired
 * arithmetic byte-for-byte, including every degenerate boundary. test_
 * bip113_bip65.c already pins the block-connect finality cutoff (the
 * block's own header time, not MTP) exhaustively. test_validation.c already
 * exercises contextual_check_transaction's expiry rejection at nHeight-1.
 * This file deliberately does NOT restate any of that. It closes four
 * specific integration gaps those files leave open:
 *
 *   1. The exact nExpiryHeight == nHeight boundary through the FULL
 *      contextual_check_transaction() wrapper (not just the domain
 *      predicate) — a tx is still valid IN the block at its own expiry
 *      height, and coinbase is exempt even when clearly "expired".
 *   2. The caller-composed DoS-score branch in contextual_check_tx.c:
 *      `is_expired_tx(tx, nHeight) ? (is_expired_tx(tx, nHeight-1) ?
 *      dosLevel : 0) : ...` — a tx that JUST expired this block scores
 *      dos=0 (no punishment for honest propagation lag); a tx that was
 *      ALREADY expired one block earlier scores the full dosLevel. This
 *      branch has no test anywhere in the suite (verified by grep).
 *   3. contextual_check_block()'s IBD short-circuit: the expiry +
 *      Sapling-structural check lives INSIDE contextual_check_transaction,
 *      which is skipped entirely when is_ibd=true (per the comment at
 *      core/modules/validation/src/check_block.c:463-465), while block-connect
 *      finality (is_final_tx) and BIP34 run UNCONDITIONALLY regardless of
 *      is_ibd. That means an EXPIRED tx is silently accepted during IBD
 *      and rejected once IBD is over — a real, intentional (mirrors
 *      zclassicd) but previously untested divergence. Flip is_ibd and
 *      watch the verdict flip on the identical block.
 *   4. nLockTime HEIGHT-domain and TIME-domain boundaries at
 *      accept_to_mempool() itself, at the EXACT next_height / tip-MTP
 *      boundary (existing accept_to_mempool coverage only used a
 *      far-future height, never the boundary, and never touched the TIME
 *      domain at all). Built on a synthetic single-block active-chain tip
 *      (active_chain_install_tip_slot — the ungated tip-slot primitive)
 *      so both the height and the MTP are exact, seed-free, and
 *      deterministic: a single-ancestor tip's median-time-past degenerates
 *      to that block's own nTime (already pinned by test_bip113_bip65.c
 *      "MTP single block returns that block's time").
 *
 * Every assertion rides on the real production predicate (domain_consensus_
 * tx_is_expired/is_final via the legacy is_expired_tx/is_final_tx inline
 * wrappers, contextual_check_transaction, contextual_check_block,
 * accept_to_mempool) — nothing here reimplements or mocks the rule. No
 * consensus predicate is changed; this file only proves the existing one
 * flips at the documented boundary (teeth) and pins the current verdict.
 */

#include "test/test_core.h"

#include "validation/contextual_check_tx.h"
#include "validation/check_block.h"
#include "validation/accept_to_mempool.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "validation/sighash.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "script/standard.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#define TELA_CHECK(name, expr) do { \
    printf("tx_expiry_locktime_adversarial: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── shared tx-shape helper ──────────────────────────────────────────
 * A minimal 1-in/1-out v4 Overwinter+Sapling tx that
 * domain_consensus_check_transaction_sapling_structural accepts as-is
 * (same shape proven by test_validation.c's make_simple_tx() /
 * "contextual_check_tx: sapling accepts valid v4"). `coinbase` selects
 * a null prevout (single input, all-zero hash + n=UINT32_MAX) so
 * transaction_is_coinbase() is true. */
static struct transaction tela_make_tx(uint32_t expiry_height,
                                       uint32_t lock_time,
                                       uint32_t sequence,
                                       bool coinbase)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.overwintered = true;
    tx.version = SAPLING_TX_VERSION;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    tx.expiry_height = expiry_height;
    tx.lock_time = lock_time;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "tela_vin");
    if (coinbase) {
        outpoint_set_null(&tx.vin[0].prevout);
    } else {
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
    }
    tx.vin[0].sequence = sequence;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx.vin[0].script_sig, sig, 2);
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "tela_vout");
    tx.vout[0].value = 50 * 100000000LL;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    return tx;
}

static void tela_free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* ── block-shape helper for the IBD short-circuit test ──────────────
 * A 2-tx block (coinbase + one overwintered/sapling spend) at `height`,
 * both txs shaped to pass the sapling-structural checks. The spend's
 * expiry_height is the caller's lever; lock_time=0/sequence=0xFFFFFFFF
 * on BOTH txs keeps finality trivially satisfied so only the expiry
 * predicate's own accept/reject shows through. */
static void tela_make_block(struct block *blk, uint32_t header_time,
                            int height, uint32_t spend_expiry_height)
{
    memset(blk, 0, sizeof(*blk));
    blk->header.nVersion = 4;
    blk->header.nTime = header_time;

    blk->num_vtx = 2;
    blk->vtx = zcl_calloc(2, sizeof(struct transaction), "tela_vtx");

    /* Coinbase: overwintered/sapling (required once overwinterActive),
     * expiry_height=0 (never expires) so it never masks the spend's
     * expiry result. BIP34: script_sig encodes height as CScriptNum. */
    struct transaction *cb = &blk->vtx[0];
    cb->overwintered = true;
    cb->version = SAPLING_TX_VERSION;
    cb->version_group_id = SAPLING_VERSION_GROUP_ID;
    cb->expiry_height = 0;
    cb->num_vin = 1;
    cb->vin = zcl_calloc(1, sizeof(struct tx_in), "tela_cb_vin");
    outpoint_set_null(&cb->vin[0].prevout);
    uint8_t cb_sig[8];
    size_t cb_len = 0;
    {
        int h = height;
        uint8_t num[4];
        size_t num_len = 0;
        if (h == 0) {
            cb_sig[0] = 0x00; cb_len = 1;
        } else {
            while (h > 0) { num[num_len++] = (uint8_t)(h & 0xff); h >>= 8; }
            if (num[num_len - 1] & 0x80) num[num_len++] = 0x00;
            cb_sig[0] = (uint8_t)num_len;
            memcpy(cb_sig + 1, num, num_len);
            cb_len = 1 + num_len;
        }
    }
    script_set(&cb->vin[0].script_sig, cb_sig, cb_len);
    cb->vin[0].sequence = 0xFFFFFFFF;
    cb->num_vout = 1;
    cb->vout = zcl_calloc(1, sizeof(struct tx_out), "tela_cb_vout");
    cb->vout[0].value = 1000000;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&cb->vout[0].script_pub_key, pk, 3);

    /* Spend: overwintered/sapling, the expiry lever under test. */
    struct transaction *sp = &blk->vtx[1];
    sp->overwintered = true;
    sp->version = SAPLING_TX_VERSION;
    sp->version_group_id = SAPLING_VERSION_GROUP_ID;
    sp->expiry_height = spend_expiry_height;
    sp->lock_time = 0;
    sp->num_vin = 1;
    sp->vin = zcl_calloc(1, sizeof(struct tx_in), "tela_sp_vin");
    memset(sp->vin[0].prevout.hash.data, 0xBB, 32);
    sp->vin[0].prevout.n = 0;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&sp->vin[0].script_sig, sig, 2);
    sp->vin[0].sequence = 0xFFFFFFFF;
    sp->num_vout = 1;
    sp->vout = zcl_calloc(1, sizeof(struct tx_out), "tela_sp_vout");
    sp->vout[0].value = 500000;
    script_set(&sp->vout[0].script_pub_key, pk, 3);
}

static void tela_free_block(struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        free(blk->vtx[i].vin);
        free(blk->vtx[i].vout);
    }
    free(blk->vtx);
}

/* ── mempool-side helpers (v1 transparent, no shielded/overwinter gates
 * in the way, so only the finality/expiry policy under test can fire) ── */

static void tela_atm_build(struct transaction *tx, const struct uint256 *prev,
                           uint32_t lock_time, uint32_t sequence)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->version = 1;
    tx->vin[0].prevout.hash = *prev;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = sequence;
    tx->vout[0].value = 1 * COIN_VALUE;
    uint8_t spk[] = {0x51}; /* OP_1 */
    script_set(&tx->vout[0].script_pub_key, spk, 1);
    tx->lock_time = lock_time;
}

static bool tela_atm_add_utxo(struct coins_view_cache *cache,
                              const struct uint256 *txid, int64_t value,
                              const struct key_id *kid)
{
    struct coins_cache_entry *entry = coins_view_cache_modify_new(cache, txid);
    if (!entry) return false;
    coins_alloc(&entry->coins, 1);
    entry->coins.vout[0].value = value;
    script_for_p2pkh(&entry->coins.vout[0].script_pub_key, kid);
    entry->coins.height = 1;
    entry->coins.version = 1;
    entry->coins.is_coinbase = false;
    return true;
}

static void tela_atm_sign(struct transaction *tx, const struct script *prev_spk,
                          int64_t amount, const struct privkey *key,
                          const struct pubkey *pub)
{
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct uint256 sighash;
    uint256_set_null(&sighash);
    signature_hash(prev_spk, tx, 0, ht, amount, 0, NULL, &sighash);

    unsigned char sig[80];
    size_t siglen = sizeof(sig);
    privkey_sign(key, &sighash, sig, &siglen);
    if (siglen > 72) siglen = 72;
    sig[siglen] = SIGHASH_ALL;
    siglen += 1;

    size_t pklen = pub->size; if (pklen > 65) pklen = 65;
    unsigned char ss_buf[1 + 73 + 1 + 65];
    size_t n = 0;
    ss_buf[n++] = (unsigned char)siglen;
    memcpy(&ss_buf[n], sig, siglen); n += siglen;
    ss_buf[n++] = (unsigned char)pklen;
    memcpy(&ss_buf[n], pub->vch, pklen); n += pklen;

    struct script ss;
    script_init(&ss);
    script_set(&ss, ss_buf, n);
    tx->vin[0].script_sig = ss;
    transaction_compute_hash(tx);
}

/* Publish a synthetic, deterministic single-ancestor tip at `height` with
 * `time` as its own nTime (so its median-time-past degenerates to `time`
 * exactly — no wall clock, no multi-block averaging). `bi` is caller-owned
 * (stack storage lives for the scope of the surrounding test) and is never
 * touched by main_state_free()/active_chain_free() (they only free the
 * chain[]-array bookkeeping, never the block_index objects it points at —
 * confirmed at core/modules/validation/src/chainstate.c active_chain_free()). */
static bool tela_install_tip(struct main_state *ms, struct block_index *bi,
                             int height, uint32_t time)
{
    block_index_init(bi);
    bi->nHeight = height;
    bi->nTime = time;
    bi->nBits = 0x1f07ffff;
    bi->pprev = NULL;
    return active_chain_install_tip_slot(&ms->chain_active, bi);
}

int test_tx_expiry_locktime_adversarial(void)
{
    int failures = 0;
    const struct chain_params *chainparams = chain_params_get();
    const struct consensus_params *cparams = &chainparams->consensus;
    const int H = 500000; /* post-Overwinter/Sapling (mainnet activation 476969) */

    /* ================================================================
     * 1. contextual_check_transaction: nExpiryHeight boundary (ZIP-203)
     * ================================================================ */

    {
        struct transaction tx = tela_make_tx((uint32_t)H, 0, 0xFFFFFFFF, false);
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = contextual_check_transaction(&tx, &vs, cparams, H, 100);
        tela_free_tx(&tx);
        TELA_CHECK("expiry_height == nHeight (still valid AT expiry) -> ACCEPT", ok);
    }

    {
        struct transaction tx = tela_make_tx((uint32_t)(H - 1), 0, 0xFFFFFFFF, false);
        struct validation_state vs;
        validation_state_init(&vs);
        bool rejected = !contextual_check_transaction(&tx, &vs, cparams, H, 100);
        bool ok = rejected && strstr(vs.reject_reason, "tx-overwinter-expired") &&
                   vs.dos == 0;
        tela_free_tx(&tx);
        TELA_CHECK("expiry_height == nHeight-1 (expired this block) -> REJECT, dos=0", ok);
    }

    {
        struct transaction tx = tela_make_tx((uint32_t)(H - 2), 0, 0xFFFFFFFF, false);
        struct validation_state vs;
        validation_state_init(&vs);
        bool rejected = !contextual_check_transaction(&tx, &vs, cparams, H, 100);
        bool ok = rejected && strstr(vs.reject_reason, "tx-overwinter-expired") &&
                   vs.dos == 100;
        tela_free_tx(&tx);
        TELA_CHECK("expiry_height == nHeight-2 (already expired last block) -> REJECT, dos=dosLevel", ok);
    }

    {
        struct transaction tx = tela_make_tx(0, 0, 0xFFFFFFFF, false);
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = contextual_check_transaction(&tx, &vs, cparams, H, 100);
        tela_free_tx(&tx);
        TELA_CHECK("expiry_height == 0 means no expiry, even far past any real height -> ACCEPT", ok);
    }

    {
        /* expiry_height far in the past: a non-coinbase tx with this
         * shape is rejected (proven by the nHeight-2 case above); the
         * ONLY difference here is the null prevout making it coinbase. */
        struct transaction tx = tela_make_tx(100, 0, 0xFFFFFFFF, true);
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = contextual_check_transaction(&tx, &vs, cparams, H, 100);
        tela_free_tx(&tx);
        TELA_CHECK("coinbase is exempt from expiry through the full wrapper -> ACCEPT", ok);
    }

    /* ================================================================
     * 2. contextual_check_block: the IBD short-circuit. Per check_block.c:
     *    "zclassicd's IBD short-circuit lives INSIDE
     *    ContextualCheckTransaction ... so only the per-tx rules are
     *    gated; finality + BIP34 below run unconditionally." Flip is_ibd
     *    on the IDENTICAL block and the verdict on an expired tx flips.
     * ================================================================ */

    {
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = H - 1;
        struct block blk;
        tela_make_block(&blk, 999999999u, H, /*spend_expiry_height=*/1000);
        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, chainparams, &prev, /*is_ibd=*/true);
        tela_free_block(&blk);
        TELA_CHECK("connect: is_ibd=true ACCEPTS a block with an expired spend (expiry check skipped)", ok);
    }

    {
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = H - 1;
        struct block blk;
        tela_make_block(&blk, 999999999u, H, /*spend_expiry_height=*/1000);
        struct validation_state state;
        validation_state_init(&state);
        bool rejected = !contextual_check_block(&blk, &state, chainparams, &prev, /*is_ibd=*/false);
        bool ok = rejected && strstr(state.reject_reason, "tx-overwinter-expired");
        tela_free_block(&blk);
        TELA_CHECK("connect: is_ibd=false REJECTS the SAME block (tx-overwinter-expired)", ok);
    }

    {
        /* Control: same block shape, not-expired spend, is_ibd=false ->
         * proves the rejection above is the expiry gate firing, not some
         * other structural mismatch in tela_make_block(). */
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = H - 1;
        struct block blk;
        tela_make_block(&blk, 999999999u, H, /*spend_expiry_height=*/(uint32_t)H);
        struct validation_state state;
        validation_state_init(&state);
        bool ok = contextual_check_block(&blk, &state, chainparams, &prev, /*is_ibd=*/false);
        if (!ok) printf("(reject_reason=%s) ", state.reject_reason);
        tela_free_block(&blk);
        TELA_CHECK("connect: is_ibd=false still ACCEPTS the block once expiry_height >= height", ok);
    }

    /* ================================================================
     * 3. accept_to_mempool: nLockTime HEIGHT-domain exact boundary.
     * ================================================================ */

    {
        struct main_state ms;
        main_state_init(&ms);
        struct block_index tip;
        bool tip_ok = tela_install_tip(&ms, &tip, /*height=*/0, /*time=*/1000000);
        const struct chain_params *p = chain_params_get();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 prev;
        memset(prev.data, 0xE1, 32);
        struct transaction tx;
        /* next_height = tip_height(0)+1 = 1; lock_time=1 == next_height:
         * the strict `lt < cutoff` early-out does NOT fire (equal, not
         * less), so a non-final sequence keeps the tx non-final. */
        tela_atm_build(&tx, &prev, /*lock_time=*/1, /*sequence=*/0xFFFFFFFEu);
        transaction_compute_hash(&tx);

        enum mempool_accept_result r = accept_to_mempool(&pool, &coins, &ms, p, &tx);
        bool ok = tip_ok && r == MEMPOOL_ACCEPT_NONFINAL;

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        main_state_free(&ms);
        TELA_CHECK("mempool: height-domain lock_time == next_height, non-final seq -> NONFINAL", ok);
    }

    {
        struct main_state ms;
        main_state_init(&ms);
        struct block_index tip;
        bool tip_ok = tela_install_tip(&ms, &tip, /*height=*/1, /*time=*/1000000);
        const struct chain_params *p = chain_params_get();

        struct privkey key;
        privkey_make_new(&key, true);
        struct pubkey pub;
        privkey_get_pubkey(&key, &pub);
        struct key_id kid = pubkey_get_id(&pub);
        struct script prev_spk;
        script_for_p2pkh(&prev_spk, &kid);

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 prev;
        memset(prev.data, 0xE2, 32);
        bool utxo_ok = tela_atm_add_utxo(&coins, &prev, 1 * COIN_VALUE, &kid);

        struct transaction tx;
        /* next_height = tip_height(1)+1 = 2; lock_time=1 < next_height=2:
         * final via the height early-out REGARDLESS of the non-final
         * sequence — proves the height-domain path itself, not a
         * sequence-override coincidence. Fully signed so a fully-final
         * tx is genuinely MEMPOOL_ACCEPT_OK (the control the task asks
         * for), not just "not NONFINAL". */
        tela_atm_build(&tx, &prev, /*lock_time=*/1, /*sequence=*/0xFFFFFFFEu);
        tela_atm_sign(&tx, &prev_spk, 1 * COIN_VALUE, &key, &pub);

        enum mempool_accept_result r = accept_to_mempool(&pool, &coins, &ms, p, &tx);
        bool ok = tip_ok && utxo_ok && r == MEMPOOL_ACCEPT_OK;

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        main_state_free(&ms);
        TELA_CHECK("mempool: height-domain lock_time == next_height-1 -> finality passes -> ACCEPT_OK", ok);
    }

    /* ================================================================
     * 4. accept_to_mempool: nLockTime TIME-domain exact boundary
     *    (existing accept_to_mempool coverage never exercises this
     *    domain at all — only the height domain, and only far from the
     *    boundary).
     * ================================================================ */

    {
        struct main_state ms;
        main_state_init(&ms);
        struct block_index tip;
        /* height value is irrelevant to the TIME domain; keep it 0 so
         * next_height=1 stays well below any activation height. */
        bool tip_ok = tela_install_tip(&ms, &tip, /*height=*/0,
                                       /*time=*/500000100u);
        const struct chain_params *p = chain_params_get();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 prev;
        memset(prev.data, 0xE3, 32);
        struct transaction tx;
        /* lock_time == tip MTP exactly (both >= LOCKTIME_THRESHOLD, so
         * the TIME domain is selected): strict `lt < cutoff` is false
         * (equal) -> falls to sequence check -> non-final seq -> non-final. */
        tela_atm_build(&tx, &prev, /*lock_time=*/500000100u, /*sequence=*/0xFFFFFFFEu);
        transaction_compute_hash(&tx);

        enum mempool_accept_result r = accept_to_mempool(&pool, &coins, &ms, p, &tx);
        bool ok = tip_ok && r == MEMPOOL_ACCEPT_NONFINAL;

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        main_state_free(&ms);
        TELA_CHECK("mempool: time-domain lock_time == tip MTP, non-final seq -> NONFINAL", ok);
    }

    {
        struct main_state ms;
        main_state_init(&ms);
        struct block_index tip;
        bool tip_ok = tela_install_tip(&ms, &tip, /*height=*/0,
                                       /*time=*/500000100u);
        const struct chain_params *p = chain_params_get();

        struct privkey key;
        privkey_make_new(&key, true);
        struct pubkey pub;
        privkey_get_pubkey(&key, &pub);
        struct key_id kid = pubkey_get_id(&pub);
        struct script prev_spk;
        script_for_p2pkh(&prev_spk, &kid);

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 prev;
        memset(prev.data, 0xE4, 32);
        bool utxo_ok = tela_atm_add_utxo(&coins, &prev, 1 * COIN_VALUE, &kid);

        struct transaction tx;
        /* lock_time = MTP-1 < cutoff: final via the time early-out
         * REGARDLESS of the non-final sequence -- proves the TIME
         * domain path itself, not the sequence override. */
        tela_atm_build(&tx, &prev, /*lock_time=*/500000099u, /*sequence=*/0xFFFFFFFEu);
        tela_atm_sign(&tx, &prev_spk, 1 * COIN_VALUE, &key, &pub);

        enum mempool_accept_result r = accept_to_mempool(&pool, &coins, &ms, p, &tx);
        bool ok = tip_ok && utxo_ok && r == MEMPOOL_ACCEPT_OK;

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        main_state_free(&ms);
        TELA_CHECK("mempool: time-domain lock_time == tip MTP - 1 -> finality passes -> ACCEPT_OK", ok);
    }

    /* ================================================================
     * 5. Control: a fully-final tx via the SEQUENCE override (all
     *    inputs 0xFFFFFFFF) is accepted regardless of a deep-future
     *    height-domain lock_time -- the other half of "final" the task
     *    asks to pin, distinct from the boundary tests above (those
     *    finalize via the height/time comparison, never via sequence).
     * ================================================================ */

    {
        struct main_state ms;
        main_state_init(&ms);
        const struct chain_params *p = chain_params_get();

        struct privkey key;
        privkey_make_new(&key, true);
        struct pubkey pub;
        privkey_get_pubkey(&key, &pub);
        struct key_id kid = pubkey_get_id(&pub);
        struct script prev_spk;
        script_for_p2pkh(&prev_spk, &kid);

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 prev;
        memset(prev.data, 0xE5, 32);
        bool utxo_ok = tela_atm_add_utxo(&coins, &prev, 1 * COIN_VALUE, &kid);

        struct transaction tx;
        tela_atm_build(&tx, &prev, /*lock_time=*/10000000u, /*sequence=*/0xFFFFFFFFu);
        tela_atm_sign(&tx, &prev_spk, 1 * COIN_VALUE, &key, &pub);

        enum mempool_accept_result r = accept_to_mempool(&pool, &coins, &ms, p, &tx);
        bool ok = utxo_ok && r == MEMPOOL_ACCEPT_OK;

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        main_state_free(&ms);
        TELA_CHECK("mempool: sequence=0xFFFFFFFF overrides a deep-future lock_time -> ACCEPT_OK", ok);
    }

    return failures;
}
