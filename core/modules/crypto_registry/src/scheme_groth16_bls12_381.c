/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "crypto_registry/crypto_registry.h"
#include "sapling/bls12_381.h"

#include <stdlib.h>

static bool registry_groth16_verify(const uint8_t *vk, size_t vk_len,
                                    const uint8_t *public_inputs,
                                    size_t pi_len,
                                    const uint8_t *proof,
                                    size_t proof_len)
{
    if (!vk || !proof || proof_len != 192 || (pi_len % 32) != 0)
        return false;

    struct groth16_vk parsed_vk = {0};
    if (!groth16_vk_read_raw(&parsed_vk, vk, vk_len))
        return false;

    struct groth16_proof parsed_proof;
    if (!groth16_proof_read(&parsed_proof, proof)) {
        free(parsed_vk.ic);
        return false;
    }

    size_t n_inputs = pi_len / 32;
    const uint64_t (*pi)[4] = (const uint64_t (*)[4])public_inputs;
    bool ok = groth16_verify(&parsed_vk, &parsed_proof, pi, n_inputs);
    free(parsed_vk.ic);
    return ok;
}

static const struct crypto_scheme g_groth16_scheme = {
    .id = CRYPTO_ZK_GROTH16_BLS12_381,
    .kind = CRYPTO_KIND_ZK,
    .status = CRYPTO_STATUS_ACTIVE,
    .name = "groth16-bls12-381",
    .impl = "in-tree core/modules/sapling/src/bls12_381.c",
    .fn.zk_verify = registry_groth16_verify,
};

__attribute__((constructor))
static void register_groth16_scheme(void)
{
    crypto_registry_register(&g_groth16_scheme);
}
