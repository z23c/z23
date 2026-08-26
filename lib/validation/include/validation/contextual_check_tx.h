/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_CONTEXTUAL_CHECK_TX_H
#define ZCL_CONTEXTUAL_CHECK_TX_H

#include "consensus/params.h"
#include "consensus/validation.h"
#include "domain/consensus/locktime.h"
#include "primitives/transaction.h"
#include <stdbool.h>

/* The pure lock-time predicates is_final_tx / is_expired_tx /
 * is_expiring_soon_tx have moved to domain/consensus/locktime.{h,c}.
 * These inline wrappers preserve the exact legacy signatures used by
 * check_block.c, txmempool.c, and the BIP113/BIP65 test corpus.
 *
 * The wrappers stay thin and inline: callers pass already-computed
 * scalars (block height, MTP cutoff) — the impure work of computing
 * those scalars from chain state lives in the wrapper's caller, not
 * here. See domain/consensus/locktime.h for the contract. */

/* TX_EXPIRING_SOON_THRESHOLD is also defined (identically) in
 * lib/validation/include/validation/main_constants.h. That definition
 * is canonical at the lib/ layer. The domain layer mirrors the same
 * literal under DOMAIN_CONSENSUS_TX_EXPIRING_SOON_THRESHOLD, and a
 * compile-time assert here pins them together so they cannot drift. */
#define LOCKTIME_THRESHOLD_TX DOMAIN_CONSENSUS_LOCKTIME_THRESHOLD

_Static_assert(DOMAIN_CONSENSUS_TX_EXPIRING_SOON_THRESHOLD == 3,
               "domain expiring-soon threshold drift");

static inline bool is_expired_tx(const struct transaction *tx, int nHeight)
{
    return domain_consensus_tx_is_expired(tx, nHeight);
}

static inline bool is_expiring_soon_tx(const struct transaction *tx,
                                       int nNextBlockHeight)
{
    return domain_consensus_tx_is_expiring_soon(tx, nNextBlockHeight);
}

static inline bool is_final_tx(const struct transaction *tx,
                                int nBlockHeight, int64_t nBlockTime)
{
    return domain_consensus_tx_is_final(tx, nBlockHeight, nBlockTime);
}

/* ── "invalid" vs "could not check" ──────────────────────────────
 *
 * contextual_check_transaction() answers a bool, and a bool cannot say
 * which of two very different things happened:
 *
 *   - the transaction is bad          → the SENDER is at fault
 *   - we were unable to judge it      → WE are at fault
 *
 * Every shielded verifier below this point fail-closes to the same
 * `false` in both cases. sprout_verify_groth16() returns false when the
 * proof is forged AND when sprout_vk is NULL because the boot loader
 * thread has not installed it yet (lib/sapling/src/sprout.c); the
 * Sapling spend/output verifiers do the same on a NULL VK
 * (lib/sapling/src/sapling.c), and the verification context allocation
 * returns NULL under memory pressure. Collapsed into one bool, the P2P
 * relay path could not tell them apart, so it charged ban-score to a
 * peer that had relayed a perfectly valid transaction while OUR keys
 * were still loading.
 *
 * The verdict form below separates them at the source. Callers that
 * attribute blame (peer scoring, block-reject bookkeeping) MUST use it
 * rather than matching on reject-reason strings: a reason string is a
 * diagnostic that will drift, while this is a type the compiler checks.
 *
 * Fail-closed by construction: UNVERIFIABLE is NOT an acceptance. The
 * transaction is still rejected and still never relayed. The only thing
 * that changes is whose fault it was. */
enum contextual_check_verdict {
    CONTEXTUAL_CHECK_PASS = 0,      /* every applicable rule verified OK */
    CONTEXTUAL_CHECK_REJECT,        /* a rule genuinely failed — sender's fault */
    CONTEXTUAL_CHECK_UNVERIFIABLE,  /* we could not check — OUR fault, never score */
};

/* True iff `tx` carries shielded components whose proofs must be verified
 * at `nHeight`, but the verifying key material needed to judge them is not
 * installed. Purely a function of LOCAL state and the tx's shape — never of
 * attacker-chosen proof bytes — which is what makes UNVERIFIABLE
 * un-steerable by a peer (see the abuse note in accept_to_mempool.h). */
bool contextual_check_tx_proofs_unverifiable(const struct transaction *tx,
                                             int nHeight);

/* Typed form. Reject reasons and DoS scores are byte-identical to the
 * bool form for every genuine consensus failure. */
enum contextual_check_verdict contextual_check_transaction_verdict(
    const struct transaction *tx,
    struct validation_state *state,
    const struct consensus_params *params,
    int nHeight,
    int dosLevel);

/* Fail-closed bool wrapper, unchanged for every caller that only needs
 * accept/reject: BOTH reject and unverifiable answer false. Callers that
 * blame someone for the false must use the verdict form above. */
bool contextual_check_transaction(const struct transaction *tx,
                                   struct validation_state *state,
                                   const struct consensus_params *params,
                                   int nHeight,
                                   int dosLevel);

/* Skip Groth16 proof verification for blocks at or below this height.
 * Set via -deferproofvalidationbelow=<hash>. Default: latest checkpoint height.
 * Value of -1 disables (verify everything).
 * Atomic: read from validation threads, written by bg_validation + boot. */
extern _Atomic int g_deferred_proof_validation_below_height;

#endif
