/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * AUTHORITY NOTE (2026-08-01 review convergence): there is exactly ONE
 * consensus Equihash predicate — domain_consensus_verify_equihash_solution
 * in the SEALED core/consensus/src/equihash.c. Every verification path in
 * the node reaches it:
 *   - header ingest / mining / index loaders: check_equihash_solution
 *     (core/chainparams/src/equihash.c, sealed) -> the domain predicate;
 *   - block validation (core/modules/validation/src/check_block.c): THIS registry
 *     shim, which only re-packs the wire bytes into a block_header and
 *     delegates to the same sealed predicate. It carries NO consensus
 *     logic of its own — no (N,K) demux, no challenge serialization.
 * core/modules/crypto/src/equihash.c is the shared, deliberately-unsealed crypto
 * PRIMITIVE (equihash_is_valid_solution + the (N,K) demux helper) that
 * the sealed predicate calls; it is pinned by the accelerator-oracle /
 * KAT gates, not by the core seal. If you are changing what counts as a
 * valid solution, the sealed domain predicate is the only place to do it.
 *
 * Two input shapes pass through this shim:
 *   - pi_len == BLOCK_HEADER_SIZE (140): the consensus shape. Re-packed
 *     into a block_header and verified by the SEALED predicate. This is
 *     the only shape block validation (check_block.c) ever submits.
 *   - anything else: non-consensus (N,K) fixtures (the registry unit
 *     test's 96,5 vector). Demuxed straight to the shared primitive —
 *     no header exists to bind, so there is no consensus meaning; this
 *     branch exists so the generic registry interface stays testable. */

#include "crypto_registry/crypto_registry.h"

#include <string.h>

#include "base/serialize_le.h"
#include "crypto/blake2b.h"
#include "crypto/equihash.h"
#include "domain/consensus/equihash.h"
#include "primitives/block.h"
#include "util/log_macros.h"

static bool registry_equihash_200_9_verify(const uint8_t *vk,
                                           size_t vk_len,
                                           const uint8_t *public_inputs,
                                           size_t pi_len,
                                           const uint8_t *proof,
                                           size_t proof_len)
{
    /* Equihash is PoW, not a ZK proof: it has no verification key. We reuse
     * the crypto_zk_verify_fn interface for registry uniformity with Groth16,
     * so vk/vk_len are ignored — the only caller (core/modules/validation/src/check_block.c)
     * already passes NULL,0. For the consensus shape, public_inputs is the
     * canonical BLOCK_HEADER_SIZE challenge input packed by
     * block_header_equihash_input() (same field order the sealed predicate
     * re-serializes internally); proof is the solution blob. */
    (void)vk;
    (void)vk_len;

    if (!public_inputs || pi_len == 0 || !proof || proof_len == 0 ||
        proof_len > MAX_SOLUTION_SIZE) {
        LOG_FAIL("crypto_registry",
                 "equihash-200-9: malformed verify inputs (pi_len=%zu proof_len=%zu)",
                 pi_len, proof_len);
    }

    if (pi_len == BLOCK_HEADER_SIZE) {
        /* CONSENSUS SHAPE: re-pack the wire bytes into a block_header and
         * delegate to the ONE sealed consensus predicate. Field order must
         * match block_header_equihash_input() in core/modules/validation/src/
         * check_block.c (version, prev, merkle, sapling-final, time, bits,
         * nonce — all little-endian, matching the consensus challenge
         * serialization). */
        struct block_header h;
        block_header_init(&h);
        const uint8_t *p = public_inputs;
        h.nVersion = zcl_read_i32_le(p);  p += 4;
        memcpy(h.hashPrevBlock.data, p, 32);        p += 32;
        memcpy(h.hashMerkleRoot.data, p, 32);       p += 32;
        memcpy(h.hashFinalSaplingRoot.data, p, 32); p += 32;
        h.nTime = zcl_read_u32_le(p); p += 4;
        h.nBits = zcl_read_u32_le(p); p += 4;
        memcpy(h.nNonce.data, p, 32);
        memcpy(h.nSolution, proof, proof_len);
        h.nSolutionSize = proof_len;

        bool valid = false;
        struct zcl_result r =
            domain_consensus_verify_equihash_solution(&h, NULL, &valid);
        if (!r.ok) {
            LOG_FAIL("crypto_registry",
                     "equihash-200-9: sealed verifier contract failure: code=%d msg=%s",
                     r.code, r.message[0] ? r.message : "(none)");
        }
        return valid;
    }

    /* NON-CONSENSUS SHAPE (unit-test (N,K) fixtures, e.g. 96,5): no block
     * header exists to bind, so demux straight to the shared primitive —
     * the same equihash_is_valid_solution the sealed predicate calls. Never
     * reached by block validation, which always packs the 140-byte header. */
    unsigned int n = 0;
    unsigned int k = 0;
    if (!equihash_solution_params(proof_len, &n, &k))
        return false;

    struct equihash_params ep;
    equihash_params_init(&ep, n, k);

    struct blake2b_ctx state;
    equihash_initialise_state(&ep, &state);
    blake2b_update(&state, public_inputs, pi_len);

    return equihash_is_valid_solution(&ep, &state, proof, proof_len);
}

static const struct crypto_scheme g_equihash_scheme = {
    .id = CRYPTO_PROOF_EQUIHASH_200_9,
    .kind = CRYPTO_KIND_ZK,
    .status = CRYPTO_STATUS_ACTIVE,
    .name = "equihash-200-9",
    .impl = "sealed core/consensus/src/equihash.c (via this shim)",
    .fn.zk_verify = registry_equihash_200_9_verify,
};

__attribute__((constructor))
static void register_equihash_scheme(void)
{
    crypto_registry_register(&g_equihash_scheme);
}
