/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/coins_math.h — pure UTXO/coins arithmetic.
 *
 * The "math" of the UTXO set: predicates and mutations that act on a
 * single `struct coins` (or a single tx_out / amount / script) and
 * never touch a cache, a database, or any I/O. This is the
 * arithmetic core that the core/modules/coins/ and core/modules/validation/ adapters
 * compose on top of.
 *
 * What lives here:
 *   - coins_math_is_pruned          : pure predicate, "are all vouts null?"
 *   - coins_math_is_available       : pure predicate, "is vout[pos] live?"
 *   - coins_math_spend              : pure mutator, sets vout[pos] = null
 *   - coins_math_cleanup            : pure mutator, trims trailing null vouts
 *   - coins_math_capture_undo       : capture (txout) and mark pruned-meta;
 *                                     extracted from update_coins() — the
 *                                     pure-on-a-single-coin slice.
 *   - amount compress/decompress    : pure bit-twiddling of int64 amounts.
 *   - script_math_compress/decompress
 *                                   : pure shape-aware (de)compression of
 *                                     P2PKH / P2SH / P2PK scripts.
 *   - script_math_compress_special_size
 *                                   : pure lookup table for compressed
 *                                     script payload sizes.
 *
 * What's NOT here (and why):
 *   - coins_alloc / coins_copy / coins_free / coins_from_transaction
 *       Allocate via the platform/modules/util safe_alloc allocator (label-tagged
 *       logging). Allocation policy + OOM logging belongs in lib/, not
 *       in pure domain math. The core/modules/coins wrappers retain those.
 *   - coins_view / coins_view_cache / coins_cache_entry
 *       Adapters (storage ports). Domain code MUST never read them.
 *   - update_coins / update_coins_with_undo
 *       Reads prevouts from a coins_view_cache, emits shadow events,
 *       updates a utxo_commitment, and grows the vout array via
 *       realloc — all I/O- or state-bound. The single
 *       PURE slice ("given a resolved coin and a pos, capture undo +
 *       spend") is exposed here as `coins_math_capture_undo`.
 *
 * Layering: this header only depends on primitives/transaction.h
 * (for `struct tx_out`), coins/coins.h (for `struct coins`),
 * coins/undo.h (for `struct tx_in_undo`), util/result.h, and the
 * script struct from script/script.h. No keys/, no chain/, no
 * crypto/, no clock, no RNG.
 *
 * Pure / replayable: every function in this header is a pure
 * function of its inputs. Calling with identical inputs always
 * yields identical outputs and side-effects (mutations to the
 * passed `struct coins` / `struct tx_in_undo` only).
 */

#ifndef ZCL_DOMAIN_CONSENSUS_COINS_MATH_H
#define ZCL_DOMAIN_CONSENSUS_COINS_MATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

struct coins;
struct tx_out;
struct tx_in_undo;
struct script;

/* ── Pure predicates / mutators on a single `struct coins` ────────── */

/* True iff `c` has no live outputs (all vouts are null sentinels).
 * Empty coins (num_vout == 0) is pruned. NULL is treated as pruned
 * (defensive: a NULL coin is "no live outputs"). */
bool coins_math_is_pruned(const struct coins *c);

/* True iff `pos < c->num_vout` AND vout[pos] is not the null sentinel.
 * NULL c -> false. */
bool coins_math_is_available(const struct coins *c, unsigned int pos);

/* Set vout[pos] to the null sentinel. Mirrors the legacy
 * `coins_spend()` contract exactly:
 *   - false if pos out of range OR vout[pos] already null (double-spend
 *     is the caller's responsibility to detect; we just no-op).
 *   - true on a successful state transition.
 *
 * Crucially: does NOT call cleanup. The legacy wrapper's long-standing
 * comment is preserved here: our C array doesn't auto-grow on
 * disconnect, so trimming after a forward spend would break the
 * subsequent `vout[pos]` access during a reorg-restore. Cleanup is the
 * caller's choice and is exposed separately via coins_math_cleanup.
 *
 * NULL c -> false. */
bool coins_math_spend(struct coins *c, uint32_t pos);

/* Trim trailing null vouts off the end of `c->vout` by lowering
 * `c->num_vout`. Does NOT reallocate. Idempotent. NULL c -> no-op. */
void coins_math_cleanup(struct coins *c);

/* Capture the undo record for a single input being spent.
 *
 * Extracted from update_coins() — this is the slice of that function
 * that is pure on a single coins entry. The caller has ALREADY resolved
 * the prevout from its view/cache adapter and grown the vout array if
 * needed; we just:
 *   1. Copy vout[pos] into undo->txout.
 *   2. Call coins_math_spend(c, pos) to null out vout[pos].
 *   3. If the coin is now pruned (all vouts null), populate
 *      undo->height / undo->coinbase / undo->version from the parent
 *      coin metadata so the chain can be reorganised back.
 *
 * Returns:
 *   ZCL_OK on success.
 *   ERR_NULL_COINS if c == NULL.
 *   ERR_NULL_UNDO  if undo == NULL.
 *   ERR_OUT_OF_RANGE if pos >= c->num_vout.
 *   ERR_ALREADY_SPENT if vout[pos] was already null (double-spend).
 *
 * Pure: no I/O, no allocation, no cache reads. Replays from inputs alone. */
struct zcl_result coins_math_capture_undo(
        struct coins *c, uint32_t pos, struct tx_in_undo *undo);

/* ── Pure amount compression (used on disk / wire) ─────────────────── */

/* Compress a uint64 amount into the variable-base-10 codec used by the
 * coin database serializer. Inverse of `coins_math_decompress_amount`.
 *
 * 0 -> 0; otherwise a packed encoding of (decimal-trailing-zeros,
 * non-zero leading digit, remainder). Pure, total function. */
uint64_t coins_math_compress_amount(uint64_t n);

/* Inverse of `coins_math_compress_amount`. Total function: any input
 * decodes to some uint64; only round-tripping through compress yields
 * a meaningful amount. */
uint64_t coins_math_decompress_amount(uint64_t x);

/* ── Pure script-shape compression ────────────────────────────────── */

/* Compress a scriptPubKey of one of four recognised shapes into a
 * minimal byte sequence in `out`:
 *
 *   P2PKH  (25 bytes, OP_DUP OP_HASH160 <20> .. OP_EQUALVERIFY OP_CHECKSIG)
 *     -> 21 bytes: 0x00 || <hash20>
 *   P2SH   (23 bytes, OP_HASH160 <20> .. OP_EQUAL)
 *     -> 21 bytes: 0x01 || <hash20>
 *   P2PK compressed   (35 bytes, push<33> <0x02/0x03||X> OP_CHECKSIG)
 *     -> 33 bytes: 0x02/0x03 || <X>
 *   P2PK uncompressed (67 bytes, push<65> <0x04 X Y> OP_CHECKSIG)
 *     -> 33 bytes: (0x04 | parity(Y)) || <X>
 *
 * On success writes `*out_len` and returns true. `out` must point to
 * at least 33 bytes of writable storage.
 *
 * On a script shape this codec doesn't recognise, returns false and
 * leaves `*out` / `*out_len` undefined (the core/modules/coins serializer falls
 * back to writing the raw script in that case).
 *
 * The uncompressed-P2PK case validates the embedded pubkey via
 * pubkey_is_fully_valid() — that call lives in contexts/wallet/modules/keys and is pure
 * (point validation, no IO). Because keys/ is below domain/ in the
 * layering, calling it from here is allowed.
 *
 * Pure: no IO, no allocation. */
bool coins_math_script_compress(const struct script *s,
                                unsigned char *out, size_t *out_len);

/* Inverse of `coins_math_script_compress`. `n_size` is the shape tag
 * (0..5; see compress for the mapping). `in_len` is the available
 * decoded payload length — at least `coins_math_script_compress_special_size(n_size)`.
 *
 * Returns true on success. False on:
 *   - unknown n_size
 *   - the n_size==4/5 uncompressed-P2PK case where the pubkey fails
 *     to decompress (contexts/wallet/modules/keys/pubkey_decompress() returned false).
 *
 * Pure: no IO. */
bool coins_math_script_decompress(struct script *s, unsigned int n_size,
                                  const unsigned char *in, size_t in_len);

/* Special-size lookup: returns the number of payload bytes consumed
 * after the shape tag for shape `n_size`.
 *   n_size 0 or 1  -> 20  (P2PKH / P2SH)
 *   n_size 2..5    -> 32  (P2PK in either compression)
 *   otherwise      ->  0  (unknown shape)
 *
 * Pure. */
unsigned int coins_math_script_compress_special_size(unsigned int n_size);

/* Error codes used by domain/consensus/coins_math.{c,h}. Stable
 * across builds; new codes are appended. Returned via zcl_result.code. */
enum domain_consensus_coins_math_err {
    DOMAIN_CONSENSUS_COINS_MATH_ERR_NULL_COINS    = 1301,
    DOMAIN_CONSENSUS_COINS_MATH_ERR_NULL_UNDO     = 1302,
    DOMAIN_CONSENSUS_COINS_MATH_ERR_OUT_OF_RANGE  = 1303,
    DOMAIN_CONSENSUS_COINS_MATH_ERR_ALREADY_SPENT = 1304,
};

#endif /* ZCL_DOMAIN_CONSENSUS_COINS_MATH_H */
