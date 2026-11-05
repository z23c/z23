/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * FlyClient — sampled proofs of a peer's advertised header history.
 * A leaf's hash and nBits are the prover's claims and ZClassic headers commit
 * no MMB root, so by themselves these proofs show only that the samples hang
 * together under the offered root. snapsync_verify_flyclient gets its assurance
 * by comparing each sample with a header this node already validated.
 *
 * This is a ZCL23 overlay protocol — no consensus changes needed.
 * Legacy zclassicd nodes never see FlyClient messages.
 *
 * Protocol:
 *   Node2 (fresh)              Node1 (at tip)
 *        ← zsnapshot (height, utxo_root, mmb_root)
 *        → zfcchallenge (random_seed)
 *        ← zfcproofs (N headers + MMB proofs)
 *        [verify each: proof valid? equals our header at that height?]
 *        → zsnapreq — if all verified
 */

#ifndef ZCL_NET_FLYCLIENT_H
#define ZCL_NET_FLYCLIENT_H

#include "chain/mmb.h"
#include "core/zcl_ids.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Number of random samples, weighted toward recent blocks. A lying prover must
 * have every sampled height land on a leaf equal to the local header there;
 * a peer with no hashpower cannot supply an alternative header, because the
 * comparison is with headers validated here, not with a target it can satisfy
 * by choosing a hash. */
#define FC_NUM_SAMPLES  50
#define FC_MAX_SAMPLES  64

/* P2P message names (≤12 chars for ZCL P2P protocol) */
#define MSG_FC_CHALLENGE  "zfcchallenge"
#define MSG_FC_PROOFS     "zfcproofs"

/* ── Challenge (verifier → prover) ──────────────────────── */

struct fc_challenge {
    uint8_t  seed[32];          /* random challenge nonce */
    uint64_t chain_length;      /* claimed number of blocks */
    uint8_t  mmb_root[32];      /* claimed MMB root to verify */
};

/* zcl_ids.h adoption (additive-only): a strongly-typed reader
 * for the raw `mmb_root[32]` field above. Wire layout is UNCHANGED — the
 * struct still carries a bare uint8_t[32] a wire memcpy writes directly;
 * this is a read-side alias so a caller that wants a `struct zcl_mmb_root`
 * (e.g. to hand to another zcl_ids-typed API) doesn't need its own memcpy.
 * `seed` stays untyped: it is a random nonce, not a content root/digest, so
 * no zcl_ids wrapper fits its semantics. */
_Static_assert(sizeof(((struct fc_challenge *)0)->mmb_root) == sizeof(struct zcl_mmb_root),
               "fc_challenge.mmb_root must stay wire-compatible with zcl_mmb_root");

static inline struct zcl_mmb_root fc_challenge_mmb_root_id(const struct fc_challenge *c)
{
    struct zcl_mmb_root r;
    memcpy(r.bytes, c->mmb_root, 32);
    return r;
}

/* ── Sample (one header + MMB proof) ────────────────────── */

struct fc_sample {
    struct mmb_leaf  leaf;      /* rich block header data */
    struct mmb_proof proof;     /* MMB inclusion proof */
};

/* ── Response (prover → verifier) ───────────────────────── */

struct fc_response {
    struct fc_sample samples[FC_MAX_SAMPLES];
    uint32_t num_samples;
};

/* Generate deterministic random sample indices from a shared seed.
 * Uses FlyClient weighted distribution: biased toward recent blocks.
 * Output: indices[0..num_indices-1], each in [0, chain_length). */
void fc_generate_indices(const uint8_t seed[32], uint64_t chain_length,
                         uint64_t *indices, uint32_t *num_indices);

/* Verify a single sample: check MMB proof against root.
 * PoW verification (Equihash) is done separately by the caller
 * since it requires the full block header with solution. */
bool fc_verify_sample(const struct fc_sample *sample,
                      const uint8_t mmb_root[32]);

/* Verify complete FlyClient response: all samples valid? */
bool fc_verify_response(const struct fc_response *resp,
                        const struct fc_challenge *challenge);

/* Build response (prover side): given the challenge, generate
 * sample indices and build MMB proofs for each.
 * Requires all_leaf_hashes from the MMB (pre-computed).
 * Returns false if any proof generation fails. */
bool fc_build_response(const struct fc_challenge *challenge,
                       const struct mmb *mmb,
                       const struct mmb_leaf *all_leaves,
                       const uint8_t (*all_leaf_hashes)[32],
                       struct fc_response *resp);

#endif
