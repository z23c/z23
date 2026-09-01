/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_PRIMITIVES_TRANSACTION_H
#define ZCL_PRIMITIVES_TRANSACTION_H

#include "core/amount.h"
#include "script/script.h"
#include "core/uint256.h"
#include "sapling/constants.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define OVERWINTER_TX_VERSION 3
#define SAPLING_TX_VERSION 4
#define OVERWINTER_VERSION_GROUP_ID 0x03C48270U
#define SAPLING_VERSION_GROUP_ID 0x892F2085U

struct outpoint {
    struct uint256 hash;
    uint32_t n;
};

static inline void outpoint_set_null(struct outpoint *op)
{
    uint256_set_null(&op->hash);
    op->n = UINT32_MAX;
}

static inline bool outpoint_is_null(const struct outpoint *op)
{
    return uint256_is_null(&op->hash) && op->n == UINT32_MAX;
}

static inline int outpoint_cmp(const struct outpoint *a, const struct outpoint *b)
{
    int r = uint256_cmp(&a->hash, &b->hash);
    if (r != 0) return r;
    if (a->n < b->n) return -1;
    if (a->n > b->n) return 1;
    return 0;
}

struct tx_in {
    struct outpoint prevout;
    struct script script_sig;
    uint32_t sequence;
};

static inline void tx_in_init(struct tx_in *in)
{
    outpoint_set_null(&in->prevout);
    in->script_sig.size = 0;
    in->sequence = UINT32_MAX;
}

static inline bool tx_in_is_final(const struct tx_in *in)
{
    return in->sequence == UINT32_MAX;
}

struct tx_out {
    int64_t value;
    struct script script_pub_key;
};

static inline void tx_out_set_null(struct tx_out *out)
{
    out->value = -1;
    out->script_pub_key.size = 0;
}

static inline bool tx_out_is_null(const struct tx_out *out)
{
    return out->value == -1;
}

struct spend_description {
    struct uint256 cv;
    struct uint256 anchor;
    struct uint256 nullifier;
    struct uint256 rk;
    unsigned char zkproof[GROTH_PROOF_SIZE];
    unsigned char spend_auth_sig[64];
};

struct output_description {
    struct uint256 cv;
    struct uint256 cm;
    struct uint256 ephemeral_key;
    unsigned char enc_ciphertext[ZC_SAPLING_ENCCIPHERTEXT_SIZE];
    unsigned char out_ciphertext[ZC_SAPLING_OUTCIPHERTEXT_SIZE];
    unsigned char zkproof[GROTH_PROOF_SIZE];
};

struct js_description {
    int64_t vpub_old;
    int64_t vpub_new;
    struct uint256 anchor;
    struct uint256 nullifiers[ZC_NUM_JS_INPUTS];
    struct uint256 commitments[ZC_NUM_JS_OUTPUTS];
    struct uint256 ephemeral_key;
    struct uint256 random_seed;
    struct uint256 macs[ZC_NUM_JS_INPUTS];
    bool use_groth;
    unsigned char proof[PHGR_PROOF_SIZE];
    unsigned char ciphertexts[ZC_NUM_JS_OUTPUTS][ZC_SPROUT_CIPHERTEXT_SIZE];
};

#define MAX_TX_INPUTS 65536
#define MAX_TX_OUTPUTS 65536
#define MAX_SHIELDED_SPENDS 4096
#define MAX_SHIELDED_OUTPUTS 4096
#define MAX_JOINSPLITS 4096

struct transaction {
    bool overwintered;
    int32_t version;
    uint32_t version_group_id;
    struct tx_in *vin;
    size_t num_vin;
    struct tx_out *vout;
    size_t num_vout;
    uint32_t lock_time;
    uint32_t expiry_height;
    int64_t value_balance;
    struct spend_description *v_shielded_spend;
    size_t num_shielded_spend;
    struct output_description *v_shielded_output;
    size_t num_shielded_output;
    struct js_description *v_joinsplit;
    size_t num_joinsplit;
    struct uint256 joinsplit_pubkey;
    unsigned char joinsplit_sig[64];
    unsigned char binding_sig[64];
    struct uint256 hash;
};

static inline bool transaction_is_coinbase(const struct transaction *tx)
{
    return tx->num_vin == 1 && outpoint_is_null(&tx->vin[0].prevout);
}

void transaction_init(struct transaction *tx);
void transaction_free(struct transaction *tx);

/* Allocate vin/vout arrays of null entries. Returns false (and leaves an
 * empty, NULL-array record) when num_vin > MAX_TX_INPUTS or
 * num_vout > MAX_TX_OUTPUTS, or on OOM. A zero count allocates NOTHING and
 * leaves that pointer NULL (no 1-byte stub), so transaction_free stays a
 * no-op — callers that later swap in a fresh array do not leak. */
bool transaction_alloc(struct transaction *tx, size_t num_vin, size_t num_vout);

/* ── Element arrays: allocated, NOT zero-filled ──────────────────────
 *
 * A struct tx_in is 10056 bytes and a struct tx_out 10016, because each
 * embeds a full MAX_SCRIPT_SIZE (10000-byte) script buffer inline. A real
 * scriptSig is ~107 bytes and a real scriptPubKey 25, so a 2954-byte block
 * off this chain allocates ~119 KB of element array — a 41x amplification,
 * and zero-filling it was 86% of the cost of deserializing that block.
 *
 * These two allocate WITHOUT the zero fill. Every caller must run
 * tx_in_init() / tx_out_set_null() over each element before use, which
 * defines every field including `.size = 0`. What is left indeterminate is
 * ONLY the script bytes at data[.size .. MAX_SCRIPT_SIZE), and nothing
 * reads those: every serializer, comparator and classifier in the tree is
 * bounded by `.size`. That property is not asserted here, it is PROVED —
 * see transaction_alloc_poison_set() and the test_script_tail_poison group.
 *
 * Return NULL for count 0 (no 1-byte stub) and on OOM.
 *
 * `label` is the allocation label, and it is a PARAMETER rather than a
 * constant on purpose: zcl_alloc_fault_should_fail() targets allocations by
 * label, so the chaos harness can only reach a caller's OOM-unwind path if
 * that caller keeps its own label. Folding every caller onto one shared
 * label silently removes "coins_vout" from the fault injector's reach — it
 * is caught by test_coins, but only because that test exists. Pass the
 * label this call site is known by. */
struct tx_in  *tx_in_array_alloc(size_t count, const char *label);
struct tx_out *tx_out_array_alloc(size_t count, const char *label);

/* Fill byte for every array handed out by tx_in_array_alloc /
 * tx_out_array_alloc; negative (the default) means "leave indeterminate",
 * which is what production runs.
 *
 * This exists so a test can drive one corpus twice under two DIFFERENT fill
 * bytes and compare every derived output — txid, block merkle root,
 * re-serialized wire bytes, script classification. Identical output under
 * two different fills is a direct proof that no consumer reads a script byte
 * past `.size`; it is what licenses skipping the zero fill at all. Returns
 * the previous value. Single-threaded test facility, not thread-safe. */
int transaction_alloc_poison_set(int fill_byte);

/* Deep copy: dst is re-initialized, then vin/vout/shielded/joinsplit arrays
 * are freshly allocated and copied (scripts copied by their .size only).
 * Returns false on any allocation failure with dst already freed to an empty
 * record. dst->hash is copied verbatim (NOT recomputed). */
bool transaction_copy(struct transaction *dst, const struct transaction *src);

/* Sum of transparent + Sprout outbound value: all vout values, plus
 * (-value_balance) when value_balance <= 0 (value sent INTO the Sapling
 * pool), plus every joinsplit vpub_old. Returns -1 if any term or running
 * total leaves the MoneyRange [0, MAX_MONEY] (logged) — a consensus
 * overflow guard, so -1 means "reject", not a valid amount. */
int64_t transaction_get_value_out(const struct transaction *tx);

struct byte_stream;

/* outpoint wire form: hash(32) || n(u32 LE). Fixed 36 bytes. */
bool outpoint_serialize(const struct outpoint *op, struct byte_stream *s);
bool outpoint_deserialize(struct outpoint *op, struct byte_stream *s);

/* tx_in wire form: prevout(36) || compact-size scriptSig len || scriptSig
 * bytes || sequence(u32 LE). DESERIALIZATION INVARIANT: a scriptSig length
 * above MAX_SCRIPT_SIZE is rejected with a logged failure (returns false).
 * The script bytes are read into the fixed in-line script buffer. */
bool tx_in_serialize(const struct tx_in *in, struct byte_stream *s);
bool tx_in_deserialize(struct tx_in *in, struct byte_stream *s);

/* tx_out wire form: value(i64 LE) || compact-size scriptPubKey len ||
 * scriptPubKey bytes. DESERIALIZATION INVARIANT: a scriptPubKey length above
 * MAX_SCRIPT_SIZE is rejected with a logged failure (returns false). */
bool tx_out_serialize(const struct tx_out *out, struct byte_stream *s);
bool tx_out_deserialize(struct tx_out *out, struct byte_stream *s);

/* Recompute tx->hash = HASH256 (double-SHA256) over the canonical
 * transaction serialization. The hash binds EXACTLY the bytes
 * transaction_serialize emits for the current version/group/flags, so it
 * covers the version-gated fields that are actually written (see
 * transaction_serialize). Called automatically at the end of
 * transaction_deserialize; call manually after mutating a tx in place. */
void transaction_compute_hash(struct transaction *tx);

/* Const sibling of transaction_compute_hash: double-SHA256 of
 * transaction_serialize(tx) into *out WITHOUT mutating tx (so const
 * validation paths can derive the txid from the actual bytes instead of
 * trusting a possibly-stale tx->hash). Returns false on a serialize or
 * allocation failure (logged); *out is untouched on false. */
bool transaction_hash_serialized(const struct transaction *tx,
                                 struct uint256 *out);

/* Sapling spend description: cv(32) || anchor(32) || nullifier(32) ||
 * rk(32) || zkproof(GROTH_PROOF_SIZE) || spendAuthSig(64). Fixed length,
 * no embedded counts. */
bool spend_description_serialize(const struct spend_description *sd, struct byte_stream *s);
bool spend_description_deserialize(struct spend_description *sd, struct byte_stream *s);

/* Sapling output description: cv(32) || cm(32) || ephemeralKey(32) ||
 * encCiphertext(ZC_SAPLING_ENCCIPHERTEXT_SIZE) ||
 * outCiphertext(ZC_SAPLING_OUTCIPHERTEXT_SIZE) || zkproof(GROTH_PROOF_SIZE).
 * Fixed length. */
bool output_description_serialize(const struct output_description *od, struct byte_stream *s);
bool output_description_deserialize(struct output_description *od, struct byte_stream *s);

/* Sprout JoinSplit description. The proof field is the ONLY length-variant:
 * GROTH_PROOF_SIZE when use_groth, else PHGR_PROOF_SIZE. The serializer keys
 * off jsd->use_groth; the deserializer is TOLD which form to expect via the
 * `use_groth` argument (it cannot be inferred from the stream) and stores it
 * back into jsd->use_groth. On the PHGR path the deserializer zero-fills the
 * full proof buffer before reading the shorter proof. Layout: vpub_old(i64
 * LE) || vpub_new(i64 LE) || anchor(32) || nullifiers[ZC_NUM_JS_INPUTS](32
 * each) || commitments[ZC_NUM_JS_OUTPUTS](32 each) || ephemeralKey(32) ||
 * randomSeed(32) || macs[ZC_NUM_JS_INPUTS](32 each) || proof(variable) ||
 * ciphertexts[ZC_NUM_JS_OUTPUTS](ZC_SPROUT_CIPHERTEXT_SIZE each). */
bool js_description_serialize(const struct js_description *jsd, struct byte_stream *s);
bool js_description_deserialize(struct js_description *jsd, bool use_groth, struct byte_stream *s);

/* Canonical ZClassic transaction serialization. The wire layout is gated by
 * the version/overwinter/group-id flags (consensus, must-never-fork):
 *   - First word is version with bit 31 = the overwintered flag; when
 *     overwintered, version_group_id(u32 LE) follows.
 *   - The Overwinter-v3 path (overwintered && group==OVERWINTER_VERSION_GROUP_ID
 *     && version==3) and the Sapling-v4 path (group==SAPLING_VERSION_GROUP_ID
 *     && version==4) are the only recognized overwintered shapes.
 *   - vin/vout (each a compact-size count + entries), then lock_time.
 *   - expiry_height is emitted only on the Overwinter-v3 OR Sapling-v4 path.
 *   - value_balance + the shielded-spend and shielded-output vectors are
 *     emitted only on the Sapling-v4 path.
 *   - JoinSplits (vector + joinsplit_pubkey(32) + joinsplit_sig(64), the
 *     last two only when count>0) are emitted only when version >= 2; the
 *     JoinSplit proof form uses Groth iff overwintered && version >= 4.
 *   - binding_sig(64) is emitted only on Sapling-v4 when there is at least
 *     one shielded spend or output.
 * Appends to `s`; returns false on the first stream failure. */
bool transaction_serialize(const struct transaction *tx, struct byte_stream *s);

/* Inverse of transaction_serialize, decoding the same version-gated layout.
 * DESERIALIZATION INVARIANTS (consensus, must-never-fork) — each rejected
 * with a logged failure (returns false): an overwintered tx whose
 * version/group-id is neither Overwinter-v3 nor Sapling-v4; counts above
 * MAX_TX_INPUTS / MAX_TX_OUTPUTS / MAX_SHIELDED_SPENDS / MAX_SHIELDED_OUTPUTS
 * / MAX_JOINSPLITS; per-script bounds inside tx_in/tx_out; OOM. The shielded
 * spend/output and joinsplit arrays are read only when the version gate
 * enables them, so a v1/v2 tx never touches those fields. tx->hash is
 * recomputed via transaction_compute_hash before returning true. `tx` is
 * re-initialized at entry; on false it may be partially built — safe to
 * transaction_free. */
bool transaction_deserialize(struct transaction *tx, struct byte_stream *s);

/* Byte length of transaction_serialize(tx) without keeping the bytes
 * (serializes into a scratch stream and returns its size). */
size_t transaction_serialize_size(const struct transaction *tx);

/* Shielded value flowing INTO the tx (the value side opposite
 * transaction_get_value_out): +value_balance when value_balance >= 0 (value
 * taken FROM the Sapling pool), plus every joinsplit vpub_new (value FROM the
 * Sprout pool). Returns -1 on a MoneyRange violation of any term or the
 * running total (logged) — a reject sentinel, not a valid amount. */
int64_t transaction_get_shielded_value_in(const struct transaction *tx);

#endif
