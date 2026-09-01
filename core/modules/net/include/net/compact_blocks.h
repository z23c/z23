/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP152 Compact Block Relay
 *
 * Reduces block relay bandwidth by ~99% for peers with overlapping
 * mempools. Instead of relaying full blocks (~1-2MB), sends:
 *   - Block header
 *   - Short transaction IDs (6 bytes each, SipHash-2-4 based)
 *   - Prefilled transactions (coinbase always included)
 *
 * Peers reconstruct the block from mempool + prefilled txs. Missing
 * txs are fetched via getblocktxn/blocktxn round-trip.
 *
 * Wire messages:
 *   sendcmpct   — negotiate compact block mode (version + high-bandwidth flag)
 *   cmpctblock  — compact block announcement/response
 *   getblocktxn — request missing transactions by index
 *   blocktxn    — respond with missing transactions
 */

#ifndef ZCL_COMPACT_BLOCKS_H
#define ZCL_COMPACT_BLOCKS_H

#include "core/uint256.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* ── BIP152 constants ──────────────────────────────────────────── */

#define COMPACT_BLOCK_VERSION 1
#define SHORT_TXID_LEN 6
#define MAX_COMPACT_BLOCK_TXNS 50000
#define MAX_GETBLOCKTXN_INDICES 50000

/* ── SipHash-2-4 ───────────────────────────────────────────────── */

/* BIP152 uses SipHash-2-4 keyed with the first 16 bytes of
 * SHA256(SHA256(header) || nonce) to compute 6-byte short txids. */
uint64_t siphash_2_4(const uint8_t key[16],
                     const uint8_t *data, size_t len);

/* ── Data structures ───────────────────────────────────────────── */

/* A prefilled transaction: index + full tx (BIP152 §2.1) */
struct prefilled_tx {
    uint16_t index;            /* differential index in the block */
    struct transaction tx;
};

/* Heap-allocated compact block (BIP152 §2.1: cmpctblock payload) */
struct compact_block_msg {
    struct block_header header;
    uint64_t nonce;

    uint8_t *short_txids;     /* flat array: num_short_txids * SHORT_TXID_LEN bytes */
    size_t num_short_txids;

    struct prefilled_tx *prefilled;
    size_t num_prefilled;

    /* Derived: SipHash key from SHA256d(header || nonce) */
    uint8_t siphash_key[16];
};

/* getblocktxn payload (BIP152 §2.3) */
struct block_txn_request {
    struct uint256 block_hash;
    uint64_t *indices;         /* absolute tx indices requested */
    size_t num_indices;
};

/* blocktxn payload (BIP152 §2.4) */
struct block_txn_response {
    struct uint256 block_hash;
    struct transaction *txs;
    size_t num_txs;
};

/* ── Lifecycle ─────────────────────────────────────────────────── */

void compact_block_msg_init(struct compact_block_msg *cb);
void compact_block_msg_free(struct compact_block_msg *cb);
void block_txn_request_init(struct block_txn_request *req);
void block_txn_request_free(struct block_txn_request *req);
void block_txn_response_init(struct block_txn_response *resp);
void block_txn_response_free(struct block_txn_response *resp);

/* ── Construction ──────────────────────────────────────────────── */

/* Build a compact block from a full block. Prefills coinbase (index 0).
 * Returns true on success. Caller must free with compact_block_msg_free. */
bool compact_block_from_block(struct compact_block_msg *cb,
                              const struct block *blk,
                              uint64_t nonce);

/* Compute the 6-byte short txid for a transaction hash using
 * the SipHash key derived from the compact block header+nonce. */
void compact_block_short_txid(const uint8_t siphash_key[16],
                              const struct uint256 *txhash,
                              uint8_t out[SHORT_TXID_LEN]);

/* Derive the SipHash key from block header + nonce.
 * key_out must be at least 16 bytes. */
void compact_block_derive_key(const struct block_header *header,
                              uint64_t nonce,
                              uint8_t key_out[16]);

/* ── Reconstruction ────────────────────────────────────────────── */

/* Attempt to reconstruct a full block from a compact block + mempool txs.
 *
 * mempool_txs/num_mempool_txs: array of transactions from the mempool.
 * extra_txs/num_extra_txs: additional recently-confirmed txs (optional, can be NULL/0).
 *
 * On success: out_block is populated, returns true.
 * On partial success: out_block is populated with available txs,
 *   missing_indices/num_missing are set, returns false.
 *   Caller should send getblocktxn for the missing indices.
 * On hard failure (bad tx count, allocation failure, out-of-range
 *   prefilled index, short-txid underrun): returns false with
 *   num_missing == 0.
 *
 * out_block is block_init()ed on EVERY return, including every hard
 * failure, so block_free(out_block) is always safe and never inspects
 * the caller's prior stack contents. Callers rely on this: an unhandled
 * early return here becomes a wild free in the caller.
 *
 * Caller must block_free(out_block) on success.
 * Caller must free(missing_indices) if num_missing > 0. */
bool compact_block_reconstruct(const struct compact_block_msg *cb,
                               const struct transaction *mempool_txs,
                               size_t num_mempool_txs,
                               const struct transaction *extra_txs,
                               size_t num_extra_txs,
                               struct block *out_block,
                               uint64_t **missing_indices,
                               size_t *num_missing);

/* Fill in missing transactions after receiving blocktxn response.
 * partial_block must have been partially filled by compact_block_reconstruct.
 * Returns true if all slots are now filled. */
bool compact_block_fill_missing(struct block *partial_block,
                                const struct block_txn_response *resp,
                                const uint64_t *missing_indices,
                                size_t num_missing);

/* ── Serialization ─────────────────────────────────────────────── */

bool compact_block_msg_serialize(const struct compact_block_msg *cb,
                                 struct byte_stream *s);
bool compact_block_msg_deserialize(struct compact_block_msg *cb,
                                   struct byte_stream *s);

bool block_txn_request_serialize(const struct block_txn_request *req,
                                 struct byte_stream *s);
bool block_txn_request_deserialize(struct block_txn_request *req,
                                   struct byte_stream *s);

bool block_txn_response_serialize(const struct block_txn_response *resp,
                                  struct byte_stream *s);
bool block_txn_response_deserialize(struct block_txn_response *resp,
                                    struct byte_stream *s);

#endif
