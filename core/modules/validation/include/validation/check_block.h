/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_VALIDATION_CHECK_BLOCK_H
#define ZCL_VALIDATION_CHECK_BLOCK_H

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "validation/contextual_check_tx.h"  /* enum contextual_check_verdict */
#include <stdbool.h>

#define MIN_BLOCK_VERSION 4

/* CheckBlockHeader — 4 context-free header checks (matches zclassicd
 * main.cpp CheckBlockHeader). Looks only at the header's own bytes,
 * never at the surrounding chain:
 *   1. nVersion >= MIN_BLOCK_VERSION                     (version-too-low)
 *   2. Equihash solution verifies, at the height-selected (N,K)
 *                                                        (invalid-solution)
 *   3. PoW: header hash satisfies nBits                  (high-hash)
 *   4. nTime <= GetAdjustedTime() + 2h                   (time-too-new)
 *
 * MUST-NEVER-FORK consensus entry point. Every full node must agree on
 * the accept/reject result for a given (header, params).
 *
 * Parameter:
 *   check_pow — when false, disables checks 2 and 3 ONLY (the Equihash
 *     solution verify and the proof-of-work hash-vs-nBits test). The
 *     version and timestamp checks still run. The ONLY legitimate reason
 *     to pass false is fast-sync of headers whose PoW is already trusted
 *     by another mechanism (a checkpoint / MMB-proved FlyClient snapshot
 *     tail), so re-verifying Equihash here is redundant work. Full
 *     validation MUST pass true; the full Equihash + PoW are re-checked
 *     later in connect_block() for any header admitted with check_pow
 *     false. */
bool check_block_header(const struct block_header *header,
                        struct validation_state *state,
                        const struct chain_params *params,
                        bool check_pow);

/* CheckBlock — 8 context-free block checks (matches zclassicd main.cpp
 * CheckBlock). Runs check_block_header first, then the block's own
 * structural checks (merkle root, size/coinbase bounds, per-tx checks,
 * aggregate sigops). All look only at the block's own bytes, never at
 * the surrounding chain.
 *
 * MUST-NEVER-FORK consensus entry point. Every full node must agree on
 * the accept/reject result for a given (block, params).
 *
 * Parameters:
 *   check_pow — forwarded verbatim to check_block_header; see its doc.
 *     When false, disables the Equihash-solution and PoW-hash checks
 *     ONLY. Pass false only when fast-syncing a block whose PoW is
 *     already trusted via a checkpoint / MMB-proved snapshot; full
 *     validation MUST pass true.
 *   check_merkle_root — when false, disables ONLY the merkle-root
 *     consistency check (the transaction merkle root recomputed from
 *     vtx must equal header->hashMerkleRoot, plus the mutation guard).
 *     The only legitimate reason to pass false is when the caller has
 *     already verified the merkle root by another path and is
 *     re-checking the same block object (avoiding redundant recompute).
 *     Full validation of an untrusted block MUST pass true.
 *   check_size_limits — when false, disables ONLY the size/coinbase
 *     bounds, the per-transaction structural checks (check_transaction
 *     over every vtx), and the aggregate sigop-count limit. The only
 *     legitimate reason to pass false is fast-sync of a block whose body
 *     is trusted via a checkpoint / SHA3 snapshot, where these
 *     structural limits are re-verified later. Full validation MUST pass
 *     true. */
bool check_block(const struct block *block,
                 struct validation_state *state,
                 const struct chain_params *params,
                 bool check_pow,
                 bool check_merkle_root,
                 bool check_size_limits);

/* ContextualCheckBlockHeader — 6 context-dependent header checks
 * (matches zclassicd main.cpp ContextualCheckBlockHeader). Unlike
 * check_block_header, these need the local ancestry (pindex_prev):
 *   1. Genesis short-circuit (all checks skipped for the genesis hash)
 *   2. Equihash solution size matches this height's (N,K) params
 *                                              (bad-equihash-solution-size)
 *   3. Difficulty: nBits == GetNextWorkRequired (bad-diffbits)
 *   4. Timestamp > median-time-past of prev 11  (time-too-old)
 *   5. Checkpoint enforcement                   (bad-fork-at-checkpoint)
 *   6. nVersion >= 4                             (bad-version)
 *
 * MUST-NEVER-FORK consensus entry point. Every full node must agree on
 * the accept/reject result for a given (header, pindex_prev, params).
 *
 * Parameter:
 *   checkpoints_enabled — when false, disables ONLY check 5 (the
 *     hardcoded-checkpoint enforcement: at a known checkpoint height the
 *     header's hash must match the embedded checkpoint, see
 *     checkpoints.h). The only legitimate reason to pass false is when
 *     checkpoint enforcement is intentionally disabled for the run
 *     (e.g. a test or a chain with no checkpoint data); full validation
 *     on the production chain MUST pass true. The difficulty and
 *     timestamp checks always run regardless.
 *
 * Note on the difficulty check (3): it is NOT individually skippable via
 * a parameter — it always runs here. GetNextWorkRequired returns
 * nProofOfWorkLimit (the weakest permissible difficulty) when its own
 * 17-block averaging window cannot be fully walked, so incomplete-window
 * nodes compare against the weakest-allowed difficulty instead of
 * blindly accepting the header.
 *
 * Note on skip_contextual (the only sanctioned way to bypass this whole
 * function): callers that legitimately accept headers without local-
 * window validation (fast-sync snapshot tail, MMB-proved headers) MUST
 * bypass this function entirely — see process_block.c's `skip_contextual`
 * gate (process_block_should_skip_contextual_header). That gate fires
 * for the post-FlyClient-snapshot tail: "If the PoW averaging window
 * cannot be walked contiguously, GetNextWorkRequired would return
 * nProofOfWorkLimit (weakest-allowed) and every honest peer's real nBits
 * would mismatch. Skip contextual check in that case; full validation
 * runs later in connect_block()." Genesis is already short-circuited
 * inside this function with an early return. */
bool contextual_check_block_header(const struct block_header *header,
                                   struct validation_state *state,
                                   const struct chain_params *params,
                                   const struct block_index *pindex_prev,
                                   bool checkpoints_enabled);

/* ContextualCheckBlock — 3 context-dependent block checks (matches
 * zclassicd main.cpp ContextualCheckBlock). Needs the local ancestry
 * (pindex_prev) to derive nHeight and the per-tx finality cutoff:
 *   1. contextual_check_transaction for every vtx (height-gated tx rules)
 *   2. per-tx finality at the block's OWN header time — zclassicd
 *      hardcodes nLockTimeFlags=0 here, so BIP113/median-time-past does
 *      NOT apply to block connection    (bad-txns-nonfinal)
 *   3. BIP34 coinbase encodes nHeight   (bad-cb-height)
 *
 * MUST-NEVER-FORK consensus entry point. Every full node must agree on
 * the accept/reject result for a given (block, pindex_prev, params,
 * chain state).
 *
 * Parameter:
 *   is_ibd — when true, skips ONLY check 1 (the per-tx
 *     contextual_check_transaction call: Overwinter expiry, network-
 *     upgrade version gating, shielded proof/sig checks). This mirrors
 *     zclassicd exactly: its ContextualCheckBlock is not IBD-gated, but
 *     ContextualCheckTransaction short-circuits during initial block
 *     download (main.cpp:941). Checks 2 (finality) and 3 (BIP34) run
 *     UNCONDITIONALLY, including under IBD, matching zclassicd. Pass
 *     is_initial_block_download(ms) on the live path; full validation of
 *     an at-tip block MUST pass false.
 *
 * As with the contextual header check, the only sanctioned full bypass
 * is for callers that defer the whole contextual pass to connect_block()
 * during a trusted fast-sync (see process_block.c's `skip_contextual`
 * gate); those callers do not invoke this function at all rather than
 * passing a flag to weaken it. */
bool contextual_check_block(const struct block *block,
                            struct validation_state *state,
                            const struct chain_params *params,
                            const struct block_index *pindex_prev,
                            bool is_ibd);

/* Typed form of the same gate. Identical consensus behaviour — it just
 * says WHY the answer was not PASS, so a caller recording a permanent
 * reject can tell a genuinely invalid block from one it merely lacked the
 * verifying keys (or the memory) to judge. Callers that persist a verdict
 * or attribute blame MUST use this rather than inspecting reject-reason
 * strings; the strings are diagnostics and will drift.
 *
 * UNVERIFIABLE is not an acceptance — contextual_check_block() still
 * answers false for it. */
enum contextual_check_verdict contextual_check_block_verdict(
                            const struct block *block,
                            struct validation_state *state,
                            const struct chain_params *params,
                            const struct block_index *pindex_prev,
                            bool is_ibd);

/* Fail-loud validation pack, check 2 helper: does the BIP34-style height
 * embedded in `coinbase`'s scriptSig equal `nHeight`? ZClassic embeds the
 * height unconditionally for every nHeight > 0 (no activation gating);
 * heights 1-16 may use the OP_N encoding. nHeight <= 0 always matches
 * (genesis has no embedded height).
 *
 * CONSENSUS-NEUTRAL BY CONSTRUCTION (E13): this is a read-only predicate
 * over OUR label vs the block's own bytes. Callers use a mismatch to HOLD
 * our pipeline (the label is wrong) — never to reject the block as
 * invalid; it never touches validation_state / REJECT codes / status
 * bits. The consensus-side BIP34 rule stays where it always was, inside
 * contextual_check_block. */
bool check_block_coinbase_height_matches(const struct transaction *coinbase,
                                         int nHeight);

#endif
