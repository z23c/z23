/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_COINS_H
#define ZCL_COINS_H

#include "primitives/transaction.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define COINS_CACHE_DIRTY (1 << 0)
#define COINS_CACHE_FRESH (1 << 1)

struct coins {
    bool is_coinbase;
    struct tx_out *vout;
    size_t num_vout;
    int height;
    int version;
};

/* Produce a pruned/empty record (vout=NULL, num_vout=0); never fails. */
void coins_init(struct coins *c);

/* Release the vout array and reset to empty (vout=NULL, num_vout=0). Leaves
 * is_coinbase/height/version untouched. Idempotent; safe on an already-empty
 * record. */
void coins_free(struct coins *c);

/* Deep copy src into dst: metadata (is_coinbase, height, version) plus a
 * freshly malloc'd copy of the vout array. dst is overwritten (NOT freed
 * first) — pass a fresh/coins_init'd dst. On OOM dst becomes an empty
 * (num_vout=0, vout=NULL) sentinel and the failure is logged; a caller that
 * trusts num_vout would then see "zero outputs", so treat an unexpected
 * empty dst as a copy failure, not a fully-spent coin. */
void coins_copy(struct coins *dst, const struct coins *src);
/* Allocate num_outputs null txouts. Returns false and leaves an empty
 * (vout=NULL, num_vout=0) record on OOM — never a partial/NULL-deref. */
bool coins_alloc(struct coins *c, size_t num_outputs);
/* Build a record from tx: skips OP_RETURN/unspendable outputs and caps at
 * 65536 outputs. Returns true on success (including a legitimately-empty
 * record). Returns false on OOM or over-cap, leaving an empty (num_vout=0)
 * record — callers MUST treat false as failure (a num_vout==0 record alone
 * is ambiguous with an all-unspendable tx, so the bool is the only reliable
 * signal). */
bool coins_from_transaction(struct coins *c, const struct transaction *tx, int height);

/* Mark output `pos` spent by nulling it in place. Returns false if pos is
 * out of range or the output is already null (already spent) — the only two
 * failure modes; otherwise true. INVARIANT (consensus): this deliberately
 * does NOT trim trailing nulls (no coins_cleanup), so a later disconnect that
 * restores a HIGHER vout index still has a slot. Forwards to the pure
 * coins_math_spend; see domain/consensus/coins_math.h. */
bool coins_spend(struct coins *c, uint32_t pos);

/* True iff `pos` is in range AND that output is non-null (unspent and
 * spendable). False for a NULL coins, out-of-range pos, or a spent slot. */
bool coins_is_available(const struct coins *c, unsigned int pos);

/* True iff every output is null (no spendable outputs remain) — i.e. the
 * record carries no live UTXO and may be erased. A NULL coins counts as
 * pruned. */
bool coins_is_pruned(const struct coins *c);

/* Trim trailing null outputs by shrinking num_vout (does NOT free or shift).
 * Used after construction and after a disconnect restores outputs, never
 * after a spend (see coins_spend). Leaves interior nulls intact. */
void coins_cleanup(struct coins *c);

struct coins_stats {
    int height;
    struct uint256 hash_block;
    uint64_t num_transactions;
    uint64_t num_tx_outputs;
    uint64_t serialized_size;
    struct uint256 hash_serialized;
    int64_t total_amount;
};

/* Zero a coins_stats to the empty-set baseline: height 0, null hashes, all
 * counts/sizes/amount 0. */
void coins_stats_init(struct coins_stats *s);

#endif
