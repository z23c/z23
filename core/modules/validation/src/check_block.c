/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * CheckBlock, CheckBlockHeader, ContextualCheckBlock[Header]
 * 21 checks matching zclassicd main.cpp:3922-4101 exactly.
 *
 * Uses REJECT_IF / REJECT_UNLESS / REJECT_CORRUPT_IF macros. */

#include "validation/check_block.h"
#include "util/log_macros.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "core/uint256.h"
#include "crypto_registry/crypto_registry.h"
#include "domain/consensus/check_block.h"
#include "event/event.h"
#include "validation/check_transaction.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_constants.h"
#include "validation/sigops.h"
#include "script/script_flags.h"
#include "util/timedata.h"
#include <assert.h>
#include <math.h>
#include <string.h>
#include "util/safe_alloc.h"
#include <stdatomic.h>

/* Emit EV_CONSENSUS_REJECT_BLOCK with block hash in the payload.
 * Payload format: "hash=<64hex> reason=<name> dos=<n>".
 * The hash is computed from the supplied header (must be non-NULL).
 * Hash lets consensus_reject_index key rejections by block hash so
 * a native reject-explanation command can answer why it was rejected. */
static void consensus_reject_block_emit(const struct block_header *header,
                                         const struct validation_state *state)
{
    if (!state || state->mode != MODE_INVALID ||
        state->reject_reason[0] == '\0') return;
    struct uint256 hash;
    if (header) {
        block_header_get_hash(header, &hash);
    } else {
        uint256_set_null(&hash);
    }
    char hex[65];
    uint256_get_hex(&hash, hex);
    event_emitf(EV_CONSENSUS_REJECT_BLOCK, 0,
                "hash=%s reason=%s dos=%d",
                hex, state->reject_reason, state->dos);
}

static bool check_block_header_impl(const struct block_header *header,
                                     struct validation_state *state,
                                     const struct chain_params *params,
                                     bool check_pow);

static bool check_block_impl(const struct block *block,
                              struct validation_state *state,
                              const struct chain_params *params,
                              bool check_pow,
                              bool check_merkle_root,
                              bool check_size_limits);

static bool contextual_check_block_header_impl(
        const struct block_header *header,
        struct validation_state *state,
        const struct chain_params *params,
        const struct block_index *pindex_prev,
        bool checkpoints_enabled);

static void write_u32_le_buf(uint8_t **p, uint32_t v)
{
    (*p)[0] = (uint8_t)(v & 0xffu);
    (*p)[1] = (uint8_t)((v >> 8) & 0xffu);
    (*p)[2] = (uint8_t)((v >> 16) & 0xffu);
    (*p)[3] = (uint8_t)((v >> 24) & 0xffu);
    *p += 4;
}

static void write_i32_le_buf(uint8_t **p, int32_t v)
{
    write_u32_le_buf(p, (uint32_t)v);
}

static bool block_header_equihash_input(const struct block_header *header,
                                        uint8_t out[BLOCK_HEADER_SIZE])
{
    if (!header || !out)
        return false;

    uint8_t *p = out;
    write_i32_le_buf(&p, header->nVersion);
    memcpy(p, header->hashPrevBlock.data, 32); p += 32;
    memcpy(p, header->hashMerkleRoot.data, 32); p += 32;
    memcpy(p, header->hashFinalSaplingRoot.data, 32); p += 32;
    write_u32_le_buf(&p, header->nTime);
    write_u32_le_buf(&p, header->nBits);
    memcpy(p, header->nNonce.data, 32); p += 32;

    return (size_t)(p - out) == BLOCK_HEADER_SIZE;
}

/* PoW entry point for block validation. Routes through the crypto
 * registry (scheme-status checks, uniformity with Groth16), but the
 * registry shim is NOT a second predicate: scheme_equihash_200_9.c only
 * re-packs these bytes back into a block_header and delegates to the ONE
 * sealed consensus predicate, domain_consensus_verify_equihash_solution
 * (core/consensus/src/equihash.c). block_header_equihash_input's field
 * order above is the consensus challenge serialization and must match
 * the shim's re-pack order exactly. */
static bool check_equihash_solution_via_registry(
    const struct block_header *header)
{
    static _Atomic(const struct crypto_scheme *) g_equihash_scheme_cache;

    const struct crypto_scheme *scheme =
        atomic_load(&g_equihash_scheme_cache);
    if (!scheme) {
        scheme = crypto_registry_lookup(CRYPTO_PROOF_EQUIHASH_200_9);
        if (scheme)
            atomic_store(&g_equihash_scheme_cache, scheme);
    }

    if (!scheme || !scheme->fn.zk_verify ||
        scheme->status == CRYPTO_STATUS_RETIRED ||
        scheme->status == CRYPTO_STATUS_UNREGISTERED) {
        LOG_FAIL("crypto_registry", "equihash-200-9 scheme unavailable");
    }

    uint8_t input[BLOCK_HEADER_SIZE];
    if (!block_header_equihash_input(header, input))
        return false;

    return scheme->fn.zk_verify(NULL, 0, input, sizeof(input),
                                header->nSolution, header->nSolutionSize);
}

/* ── CheckBlockHeader (4 checks) ──────────────────────────────── */

bool check_block_header(const struct block_header *header,
                        struct validation_state *state,
                        const struct chain_params *params,
                        bool check_pow)
{
    bool ok = check_block_header_impl(header, state, params, check_pow);
    if (!ok) consensus_reject_block_emit(header, state);
    return ok;
}

static bool check_block_header_impl(const struct block_header *header,
                                     struct validation_state *state,
                                     const struct chain_params *params,
                                     bool check_pow)
{
    REJECT_IF(header->nVersion < MIN_BLOCK_VERSION,
              state, 100, "version-too-low");

    if (check_pow) {
        REJECT_IF(!check_equihash_solution_via_registry(header),
                  state, 100, "invalid-solution");

        struct uint256 hash;
        block_header_get_hash(header, &hash);
        REJECT_IF(!CheckProofOfWork(hash, header->nBits, &params->consensus),
                  state, 50, "high-hash");
    }

    REJECT_INVALID_IF(
        block_header_get_time(header) > GetAdjustedTime() + 2 * 60 * 60,
        state, "time-too-new");

    return true;
}

/* ── CheckBlock (8 checks) ─────────────────────────────────────── */

bool check_block(const struct block *block,
                 struct validation_state *state,
                 const struct chain_params *params,
                 bool check_pow,
                 bool check_merkle_root,
                 bool check_size_limits)
{
    bool ok = check_block_impl(block, state, params,
                                check_pow, check_merkle_root,
                                check_size_limits);
    /* check_block_impl calls check_transaction and check_block_header
     * internally, both of which already emit their own rejection event
     * on failure. Emit the outer block-level event only when the
     * failure arose directly inside check_block_impl (not forwarded
     * from a nested emission) — detectable by the reason string being
     * set to a block-scoped reason rather than a tx-scoped one. The
     * cheap proxy: emit unconditionally here and accept the small risk
     * of a duplicate event under `consensus.reject_tx` + `consensus.reject_block`
     * for txs inside blocks, which is actually useful diagnostic data
     * (tells us whether the rejected tx is in-mempool or in-block). */
    if (!ok) consensus_reject_block_emit(&block->header, state);
    return ok;
}

static bool check_block_impl(const struct block *block,
                              struct validation_state *state,
                              const struct chain_params *params,
                              bool check_pow,
                              bool check_merkle_root,
                              bool check_size_limits)
{
    if (!check_block_header(&block->header, state, params, check_pow))
        LOG_FAIL("check_block", "check_block_header failed");

    /* Merkle-root and size/coinbase/sigops are pure structural checks:
     * they look only at the block's own bytes. Both have been
     * extracted into the hexagonal domain layer
     * (domain/consensus/check_block). The wrapper still owns the
     * rejection-emission style (DoS-or-corrupt flag, REJECT_* macros)
     * so the byte-identical reject_reason strings reach the P2P layer
     * unchanged. */
    if (check_merkle_root) {
        char domain_reason[DOMAIN_CHECK_BLOCK_REASON_MAX] = {0};
        int  domain_dos = 0;
        struct zcl_result r = domain_consensus_check_block_merkle_root(
                block, domain_reason, sizeof(domain_reason), &domain_dos);
        if (!r.ok) {
            /* Both merkle rejections are corruption-class in the legacy
             * code (REJECT_CORRUPT_IF). Out-of-memory remains a fatal
             * error rather than a peer-rejection. */
            if (r.code == DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_OUT_OF_MEMORY)
                REJECT_FATAL(state, "out-of-memory");
            REJECT_CORRUPT_IF(true, state, domain_dos, domain_reason);
        }
    }

    if (check_size_limits) {
        /* (1) num_vtx bounds + coinbase placement. Legacy used plain
         * REJECT_IF (corruption flag = false) for all three. */
        {
            char domain_reason[DOMAIN_CHECK_BLOCK_REASON_MAX] = {0};
            int  domain_dos = 0;
            struct zcl_result r =
                    domain_consensus_check_block_size_and_coinbase(
                            block, domain_reason, sizeof(domain_reason),
                            &domain_dos);
            if (!r.ok)
                REJECT_IF(true, state, domain_dos, domain_reason);
        }

        /* (2) Per-tx structural checks. Order preserved from legacy:
         * runs AFTER the block-shape gates, BEFORE the sigops total.
         * In-block variant: the empirical oversize grandfather applies
         * (413 canonical post-Sapling txs above 102000 — zclassicd
         * live-behavior parity; everything else stays strict). */
        for (size_t i = 0; i < block->num_vtx; i++) {
            if (!check_transaction_in_block(&block->vtx[i], state))
                LOG_FAIL("check_block", "check_transaction failed for tx[%zu]", i);
        }

        /* (3) Aggregate sigop count. Legacy used REJECT_CORRUPT_IF
         * (corruption flag = true), so we preserve that here. */
        {
            char domain_reason[DOMAIN_CHECK_BLOCK_REASON_MAX] = {0};
            int  domain_dos = 0;
            struct zcl_result r = domain_consensus_check_block_sigops(
                    block, domain_reason, sizeof(domain_reason),
                    &domain_dos);
            if (!r.ok)
                REJECT_CORRUPT_IF(true, state, domain_dos, domain_reason);
        }
    }

    return true;
}

/* ── ContextualCheckBlockHeader (6 checks) ─────────────────────── */

bool contextual_check_block_header(const struct block_header *header,
                                   struct validation_state *state,
                                   const struct chain_params *params,
                                   const struct block_index *pindex_prev,
                                   bool checkpoints_enabled)
{
    bool ok = contextual_check_block_header_impl(header, state, params,
                                                 pindex_prev,
                                                 checkpoints_enabled);
    /* Emit on EVERY contextual failure path (bad-equihash-solution-size,
     * bad-diffbits, time-too-old, bad-fork-at-checkpoint, bad-version) —
     * the REJECT_* macros stamp state->reject_reason, which the emit
     * helper forwards. The bad-diffbits path additionally emits a
     * detail-rich row inline (header/expected/prev nBits). Mirrors the
     * check_block_header()/check_block() sibling wrappers. */
    if (!ok) consensus_reject_block_emit(header, state);
    return ok;
}

static bool contextual_check_block_header_impl(
        const struct block_header *header,
        struct validation_state *state,
        const struct chain_params *params,
        const struct block_index *pindex_prev,
        bool checkpoints_enabled)
{
    struct uint256 hash;
    block_header_get_hash(header, &hash);

    /* Genesis: skip all contextual checks */
    if (uint256_eq(&hash, &params->consensus.hashGenesisBlock))
        return true;

    if (!pindex_prev)
        REJECT_FATAL(state, "prev-block-index-null");

    int nHeight = pindex_prev->nHeight + 1;

    /* Equihash solution size for this height's (N,K) params.
     * Pre-Bubbles (h<585318): Equihash(200,9) → 1344 bytes.
     * Post-Bubbles:           Equihash(192,7) → 400 bytes.
     * Accept headers with no solution (sol_size==0) — the full solution
     * is verified when the block is downloaded. */
    size_t sol_size = header->nSolutionSize;
    if (sol_size > 0) {
        unsigned int eh_n = chain_params_equihash_n(params, nHeight);
        unsigned int eh_k = chain_params_equihash_k(params, nHeight);
        size_t expected = ((size_t)1 << eh_k) * (eh_n / (eh_k + 1) + 1) / 8;
        REJECT_IF(sol_size != expected,
                  state, 100, "bad-equihash-solution-size");
    }

    /* Difficulty check — always verify. The code had a
     * `skip_diffbits` goto that silently bypassed this check whenever the
     * 28-ancestor window was incomplete.  That was a real consensus hole:
     * a peer could ship a header whose nBits claimed trivial difficulty,
     * and if our local pprev chain had any NULL in the first 28 ancestors
     * the header rode through unchecked.
     *
     * The replacement policy: always run GetNextWorkRequired.  It returns
     * `nProofOfWorkLimit` (the weakest permissible difficulty) when its
     * own 17-block averaging window cannot be fully walked, so
     * incomplete-window nodes compare against the weakest-allowed
     * difficulty instead of blindly accepting the header.  Callers that
     * legitimately accept headers without local-window validation (fast-
     * sync snapshot tail, MMB-proved headers) MUST bypass this function
     * entirely — see process_block.c's `skip_contextual` gate.  Genesis
     * is already short-circuited above with an early `return true`. */
    {
        unsigned int expected_bits = GetNextWorkRequired(pindex_prev, header,
                                                         &params->consensus);
        if (header->nBits != expected_bits) {
            /* Carry the full diffbits detail (header vs expected nBits,
             * prev height/bits) on a structured event instead of stdout —
             * the wrapper's consensus_reject_block_emit() also fires with
             * hash/reason/dos, so both rows key the same rejection. */
            char hex[65];
            uint256_get_hex(&hash, hex);
            event_emitf(EV_CONSENSUS_REJECT_BLOCK, 0,
                        "hash=%s reason=bad-diffbits header_nbits=0x%08x "
                        "expected_nbits=0x%08x prev_height=%d prev_bits=0x%08x",
                        hex, header->nBits, expected_bits,
                        pindex_prev->nHeight, pindex_prev->nBits);
            REJECT_IF(true, state, 100, "bad-diffbits");
        }
    }

    /* Timestamp must be after median of previous 11 blocks */
    REJECT_INVALID_IF(
        block_header_get_time(header) <=
            block_index_get_median_time_past(pindex_prev),
        state, "time-too-old");

    /* Checkpoint enforcement — see checkpoints.h for the policy
     * (exact-height match at known heights; silent pass for heights
     * with no checkpoint). */
    if (checkpoints_enabled) {
        REJECT_CHECKPOINT_IF(
            !checkpoints_validate_header(&params->checkpointData,
                                          nHeight, &hash),
            state, 100, "bad-fork-at-checkpoint");
    }

    REJECT_OBSOLETE_IF(header->nVersion < 4, state, "bad-version");

    return true;
}

/* ── BIP34 coinbase height encoding ────────────────────────────── */

static bool bip34_check_coinbase_height(const struct transaction *coinbase,
                                        int nHeight)
{
    if (coinbase->num_vin == 0)
        LOG_FAIL("check_block", "coinbase has no inputs");

    const struct script *sig = &coinbase->vin[0].script_sig;
    if (nHeight <= 0)
        return true;
    if (sig->size == 0)
        LOG_FAIL("check_block", "coinbase script_sig is empty at height %d", nHeight);

    /* Early blocks (height 1-16) may use OP_N (0x51-0x60) encoding */
    if (nHeight >= 1 && nHeight <= 16) {
        unsigned char op_n = 0x50 + (unsigned char)nHeight;
        if (sig->data[0] == op_n)
            return true;
    }

    /* Encode height as CScriptNum: minimal signed little-endian */
    unsigned char expect[6];
    size_t expect_len = 0;
    {
        int h = nHeight;
        unsigned char num[4];
        size_t num_len = 0;
        while (h > 0) {
            num[num_len++] = (unsigned char)(h & 0xff);
            h >>= 8;
        }
        if (num_len > 0 && (num[num_len - 1] & 0x80))
            num[num_len++] = 0x00;
        expect[0] = (unsigned char)num_len;
        memcpy(expect + 1, num, num_len);
        expect_len = 1 + num_len;
    }

    if (sig->size < expect_len)
        LOG_FAIL("check_block", "coinbase sig data too short: size=%zu expected=%zu at height %d",
                 sig->size, expect_len, nHeight);
    return memcmp(sig->data, expect, expect_len) == 0;
}

/* Validation-pack export (see check_block.h): the same parser, exposed as
 * a consensus-neutral label predicate for the per-connect check. */
bool check_block_coinbase_height_matches(const struct transaction *coinbase,
                                         int nHeight)
{
    if (!coinbase)
        return true; /* nothing to compare — caller skips, never holds */
    return bip34_check_coinbase_height(coinbase, nHeight);
}

/* ── ContextualCheckBlock (3 checks) ──────────────────────────── */

/* Bool-returning body so REJECT_UNLESS / LOG_FAIL (both expand to
 * `return false`) stay correct; *local_fault distinguishes "this block is
 * invalid" from "we could not check it". See enum contextual_check_verdict. */
static bool contextual_check_block_impl(const struct block *block,
                                        struct validation_state *state,
                                        const struct chain_params *params,
                                        const struct block_index *pindex_prev,
                                        bool is_ibd,
                                        bool *local_fault)
{
    int nHeight = pindex_prev == NULL ? 0 : pindex_prev->nHeight + 1;

    *local_fault = false;

    for (size_t i = 0; i < block->num_vtx; i++) {
        /* zclassicd's IBD short-circuit lives INSIDE
         * ContextualCheckTransaction (main.cpp:941), so only the per-tx
         * rules are gated; finality + BIP34 below run unconditionally. */
        if (!is_ibd) {
            enum contextual_check_verdict v =
                contextual_check_transaction_verdict(&block->vtx[i], state,
                                                     &params->consensus,
                                                     nHeight, 100);
            if (v != CONTEXTUAL_CHECK_PASS) {
                *local_fault = (v == CONTEXTUAL_CHECK_UNVERIFIABLE);
                LOG_FAIL("check_block", "contextual_check_transaction failed for tx[%zu] at height %d", i, nHeight);
            }
        }

        /* Block-connect finality cutoff = the block's OWN header timestamp,
         * matching zclassicd's ContextualCheckBlock exactly: it hardcodes
         * `nLockTimeFlags = 0`, so the LOCKTIME_MEDIAN_TIME_PAST branch is
         * never taken and the cutoff is `block.GetBlockTime()`
         * (zclassic-cpp/src/main.cpp:4083-4087). BIP113/median-time-past
         * applies ONLY to mempool acceptance (accept_to_mempool), NOT to
         * block connection. Using MTP here (always <= header time) made c23
         * stricter than zclassicd and could reject a block it accepts for a
         * tx with nLockTime in [MTP, blockTime) → consensus fork. */
        int64_t nLockTimeCutoff = block_header_get_time(&block->header);
        REJECT_UNLESS(is_final_tx(&block->vtx[i], nHeight, nLockTimeCutoff),
                      state, 10, "bad-txns-nonfinal");
    }

    if (nHeight > 0) {
        REJECT_UNLESS(bip34_check_coinbase_height(&block->vtx[0], nHeight),
                      state, 100, "bad-cb-height");
    }

    return true;
}

enum contextual_check_verdict contextual_check_block_verdict(
                            const struct block *block,
                            struct validation_state *state,
                            const struct chain_params *params,
                            const struct block_index *pindex_prev,
                            bool is_ibd)
{
    bool local_fault = false;
    if (contextual_check_block_impl(block, state, params, pindex_prev,
                                    is_ibd, &local_fault))
        return CONTEXTUAL_CHECK_PASS;
    return local_fault ? CONTEXTUAL_CHECK_UNVERIFIABLE
                       : CONTEXTUAL_CHECK_REJECT;
}

bool contextual_check_block(const struct block *block,
                            struct validation_state *state,
                            const struct chain_params *params,
                            const struct block_index *pindex_prev,
                            bool is_ibd)
{
    return contextual_check_block_verdict(block, state, params, pindex_prev,
                                          is_ibd) == CONTEXTUAL_CHECK_PASS;
}
