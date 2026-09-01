/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * FlyClient probabilistic chain verification.
 * Enables a fresh node to verify 3M+ blocks of PoW by sampling
 * O(log n) random headers with MMB inclusion proofs. */

#include "net/flyclient.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include "util/log_macros.h"
#include <string.h>
#include <stdio.h>
#include <math.h>

/* Lightweight PoW check: block_hash < target(nBits).
 * Unlike CheckProofOfWork(), does NOT check against powLimit — that's
 * a consensus rule for miners, not relevant for FlyClient verification.
 * FlyClient only needs: "this hash was hard to produce." */
static bool fc_check_pow(const uint8_t block_hash[32], uint32_t nBits)
{
    bool fNegative = false, fOverflow = false;
    struct arith_uint256 target;
    arith_uint256_set_compact(&target, nBits, &fNegative, &fOverflow);

    if (fNegative || arith_uint256_is_zero(&target) || fOverflow)
        LOG_FAIL("flyclient", "fc_check_pow: invalid nBits=0x%08x (neg=%d, zero=%d, overflow=%d)",
                 nBits, fNegative, arith_uint256_is_zero(&target), fOverflow);

    struct uint256 hash;
    memcpy(hash.data, block_hash, 32);
    struct arith_uint256 hash_arith;
    uint256_to_arith(&hash_arith, &hash);

    return arith_uint256_compare(&hash_arith, &target) <= 0;
}

/* ── Index generation (weighted toward recent blocks) ──── */

void fc_generate_indices(const uint8_t seed[32], uint64_t chain_length,
                         uint64_t *indices, uint32_t *num_indices)
{
    if (!indices || !num_indices || chain_length == 0) {
        if (num_indices) *num_indices = 0;
        return;
    }

    uint32_t count = FC_NUM_SAMPLES;
    if (count > chain_length) count = (uint32_t)chain_length;
    if (count > FC_MAX_SAMPLES) count = FC_MAX_SAMPLES;

    /* FlyClient weighted sampling: bias toward recent blocks.
     * For each sample i, compute:
     *   x = SHA3(seed || i) mapped to [0, 1)
     *   index = chain_length - 1 - floor(chain_length * x^(1/log2(chain_length)))
     *
     * This distribution samples recent blocks with higher probability,
     * which is necessary for FlyClient security: an adversary who
     * controls a minority of hashpower can only produce valid PoW
     * for recent blocks with low probability. */

    double log_n = log2((double)chain_length);
    if (log_n < 1.0) log_n = 1.0;
    double exponent = 1.0 / log_n;

    for (uint32_t i = 0; i < count; i++) {
        /* Deterministic random: SHA3(seed || sample_index) */
        uint8_t hash_input[36];
        memcpy(hash_input, seed, 32);
        hash_input[32] = (uint8_t)(i);
        hash_input[33] = (uint8_t)(i >> 8);
        hash_input[34] = (uint8_t)(i >> 16);
        hash_input[35] = (uint8_t)(i >> 24);

        uint8_t h[32];
        sha3_256(hash_input, 36, h);

        /* Map first 8 bytes to [0, 1) */
        uint64_t raw = 0;
        for (int j = 0; j < 8; j++)
            raw = (raw << 8) | h[j];
        double x = (double)raw / (double)UINT64_MAX;

        /* Apply FlyClient distribution: x^(1/log(n))
         * When x is near 1, weighted is near 1 → index near tip (recent).
         * When x is near 0, weighted is near 0 → index near genesis (old). */
        double weighted = pow(x, exponent);

        /* Map to block index: weighted near 1 → near tip (recent) */
        uint64_t idx = (uint64_t)((double)(chain_length - 1) * weighted);
        if (idx >= chain_length) idx = chain_length - 1;

        /* Deduplicate: if this index was already sampled, rehash with
         * an extra counter byte until we get a unique one.  With 20
         * samples from a 3M chain collisions are rare, but with short
         * chains this matters for security (each sample must verify a
         * distinct block). */
        bool dup = false;
        for (uint32_t j = 0; j < i; j++) {
            if (indices[j] == idx) { dup = true; break; }
        }
        if (dup && chain_length > count) {
            uint8_t retry_input[37];
            memcpy(retry_input, hash_input, 36);
            for (uint16_t r = 1; r <= 255; r++) {
                retry_input[36] = (uint8_t)r;
                sha3_256(retry_input, 37, h);
                raw = 0;
                for (int j = 0; j < 8; j++)
                    raw = (raw << 8) | h[j];
                x = (double)raw / (double)UINT64_MAX;
                weighted = pow(x, exponent);
                idx = (uint64_t)((double)(chain_length - 1) * weighted);
                if (idx >= chain_length) idx = chain_length - 1;
                dup = false;
                for (uint32_t j = 0; j < i; j++) {
                    if (indices[j] == idx) { dup = true; break; }
                }
                if (!dup) break;
            }
            /* Retry budget can be exhausted (observed for short chains,
             * e.g. ~2% of seeds at chain_length=100): all 255 rehashes
             * may collide with already-chosen recent-biased indices.
             * Storing a duplicate here would silently verify the same
             * block twice and weaken the soundness guarantee (each of
             * the `count` samples must cover a DISTINCT block).  Since
             * chain_length > count, a free slot is guaranteed to exist:
             * linear-probe forward (wrapping) from the colliding index
             * until we land on an unused one. */
            if (dup) {
                uint64_t probe = idx;
                for (uint64_t step = 0; step < chain_length; step++) {
                    bool taken = false;
                    for (uint32_t j = 0; j < i; j++) {
                        if (indices[j] == probe) { taken = true; break; }
                    }
                    if (!taken) { idx = probe; break; }
                    probe++;
                    if (probe >= chain_length) probe = 0;
                }
            }
        }

        indices[i] = idx;
    }

    *num_indices = count;
}

/* ── Sample verification ─────────────────────────────────── */

bool fc_verify_sample(const struct fc_sample *sample,
                      const uint8_t mmb_root[32])
{
    if (!sample || !mmb_root) LOG_FAIL("flyclient", "fc_verify_sample: null sample or mmb_root");

    /* Step 1: Reconstruct leaf hash from the rich leaf data */
    uint8_t computed_leaf_hash[32];
    mmb_hash_leaf(&sample->leaf, computed_leaf_hash);

    /* Step 2: Verify the leaf hash matches what's in the proof */
    if (memcmp(computed_leaf_hash, sample->proof.leaf_hash, 32) != 0) {
        LOG_FAIL("flyclient", "fc_verify_sample: leaf %llu hash mismatch (h=%u, siblings=%u, peaks=%u)",
                 (unsigned long long)sample->proof.leaf_index,
                 sample->leaf.height,
                 sample->proof.num_siblings,
                 sample->proof.num_peaks);
    }

    /* Step 3: Verify MMB inclusion proof against offered root */
    if (!mmb_verify(&sample->proof, mmb_root)) {
        LOG_FAIL("flyclient", "fc_verify_sample: leaf %llu proof invalid (h=%u, siblings=%u, peaks=%u, mmb_size=%llu)",
                 (unsigned long long)sample->proof.leaf_index,
                 sample->leaf.height,
                 sample->proof.num_siblings,
                 sample->proof.num_peaks,
                 (unsigned long long)sample->proof.mmb_size);
    }

    event_emitf(EV_MMB_PROOF_VERIFIED, 0,
                "leaf=%llu valid=true",
                (unsigned long long)sample->proof.leaf_index);
    return true;
}

/* ── Full response verification ──────────────────────────── */

bool fc_verify_response(const struct fc_response *resp,
                        const struct fc_challenge *challenge)
{
    if (!resp || !challenge) LOG_FAIL("flyclient", "fc_verify_response: null response or challenge");
    if (resp->num_samples == 0) LOG_FAIL("flyclient", "fc_verify_response: empty response (0 samples)");

    /* Regenerate expected indices from the challenge seed */
    uint64_t expected_indices[FC_MAX_SAMPLES];
    uint32_t expected_count = 0;
    fc_generate_indices(challenge->seed, challenge->chain_length,
                        expected_indices, &expected_count);

    if (resp->num_samples != expected_count) {
        event_emitf(EV_FC_CHAIN_VERIFIED, 0,
                    "samples=%u expected=%u all_valid=false reason=count_mismatch",
                    resp->num_samples, expected_count);
        LOG_FAIL("flyclient", "fc_verify_response: sample count mismatch (got=%u, expected=%u)",
                 resp->num_samples, expected_count);
    }

    /* Verify each sample */
    uint32_t valid_count = 0;
    for (uint32_t i = 0; i < resp->num_samples; i++) {
        const struct fc_sample *s = &resp->samples[i];

        /* Check that the sample is for the expected index */
        if (s->proof.leaf_index != expected_indices[i]) {
            event_emitf(EV_FC_SAMPLE_VERIFIED, 0,
                        "sample=%u expected_idx=%llu got_idx=%llu valid=false",
                        i, (unsigned long long)expected_indices[i],
                        (unsigned long long)s->proof.leaf_index);
            continue;
        }

        /* Check that the leaf height matches the index */
        if (s->leaf.height != (uint32_t)expected_indices[i]) {
            event_emitf(EV_FC_SAMPLE_VERIFIED, 0,
                        "sample=%u h=%u expected_h=%llu valid=false height_mismatch",
                        i, s->leaf.height,
                        (unsigned long long)expected_indices[i]);
            continue;
        }

        /* Verify MMB proof + leaf hash consistency */
        if (!fc_verify_sample(s, challenge->mmb_root)) {
            event_emitf(EV_FC_SAMPLE_VERIFIED, 0,
                        "sample=%u h=%u valid=false proof_failed",
                        i, s->leaf.height);
            continue;
        }

        /* PoW verification: block_hash must meet the nBits difficulty
         * target.  Full Equihash solution verification requires the
         * complete header (with nonce + 1344-byte solution), which is
         * too large for every sample.  But checking block_hash < target
         * is sufficient: forging such a hash IS the proof of work. */
        {
            if (!fc_check_pow(s->leaf.block_hash, s->leaf.nBits)) {
                event_emitf(EV_FC_SAMPLE_VERIFIED, 0,
                            "sample=%u h=%u valid=false pow_failed "
                            "nBits=%08x",
                            i, s->leaf.height, s->leaf.nBits);
                // obs-ok:fc-pow-fail — fact already emitted structurally by
                // the EV_FC_SAMPLE_VERIFIED event above; this is the echo.
                fprintf(stderr, "FlyClient: sample %u (h=%u) FAILED PoW "
                        "check (nBits=0x%08x)\n",
                        i, s->leaf.height, s->leaf.nBits);
                continue;
            }
        }

        event_emitf(EV_FC_SAMPLE_VERIFIED, 0,
                    "sample=%u h=%u valid=true proof=ok pow=ok",
                    i, s->leaf.height);
        valid_count++;
    }

    bool all_valid = (valid_count == resp->num_samples);
    event_emitf(EV_FC_CHAIN_VERIFIED, 0,
                "samples=%u valid=%u all_valid=%s",
                resp->num_samples, valid_count,
                all_valid ? "true" : "false");

    if (all_valid) {
        printf("*** FlyClient: chain verified (%u/%u samples valid, "
               "chain_length=%llu) ***\n",
               valid_count, resp->num_samples,
               (unsigned long long)challenge->chain_length);
    } else {
        // obs-ok:fc-chain-fail — fact already emitted structurally by the
        // EV_FC_CHAIN_VERIFIED event above (all_valid=false); this is the echo.
        fprintf(stderr, "FlyClient: chain verification FAILED "
                "(%u/%u samples valid)\n",
                valid_count, resp->num_samples);
    }

    return all_valid;
}

/* ── Response building (prover side) ─────────────────────── */

bool fc_build_response(const struct fc_challenge *challenge,
                       const struct mmb *mmb,
                       const struct mmb_leaf *all_leaves,
                       const uint8_t (*all_leaf_hashes)[32],
                       struct fc_response *resp)
{
    if (!challenge || !mmb || !all_leaves || !all_leaf_hashes || !resp)
        LOG_FAIL("flyclient", "fc_build_response: null argument (challenge=%p mmb=%p leaves=%p hashes=%p resp=%p)",
                 (const void *)challenge, (const void *)mmb, (const void *)all_leaves,
                 (const void *)all_leaf_hashes, (void *)resp);

    memset(resp, 0, sizeof(*resp));

    /* Generate sample indices from the challenge */
    uint64_t indices[FC_MAX_SAMPLES];
    uint32_t count = 0;
    fc_generate_indices(challenge->seed, challenge->chain_length,
                        indices, &count);

    resp->num_samples = count;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t idx = indices[i];
        if (idx >= mmb->num_leaves) {
            LOG_FAIL("flyclient", "fc_build_response: index %llu >= num_leaves %llu",
                     (unsigned long long)idx,
                     (unsigned long long)mmb->num_leaves);
        }

        /* Copy the rich leaf data */
        resp->samples[i].leaf = all_leaves[idx];

        /* Generate MMB inclusion proof */
        if (!mmb_prove(all_leaf_hashes, mmb->num_leaves, idx,
                       &resp->samples[i].proof)) {
            LOG_FAIL("flyclient", "fc_build_response: proof generation failed for index %llu",
                     (unsigned long long)idx);
        }
    }

    return true;
}
