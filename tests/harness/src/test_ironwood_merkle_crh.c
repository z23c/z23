/* purpose: Check Orchard MerkleCRH against upstream real-note roots. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_merkle_crh.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

/* Orchard 0.16.0 / sinsemilla 0.2.0 oracle on the two actual commitments in
 * the public protected-reward fixture. Parameter SHA256 c742f4c76e3727de7bc93bf446a50e9a84efa77a8987d96f409d6c464ed8262b. */
static bool empty_roots(const uint8_t *params, uint8_t empty[33][32])
{
    memset(empty, 0, 33 * 32); empty[0][0] = 2;
    for (unsigned i = 0; i < 32; ++i)
        if (!ironwood_merkle_crh(i, empty[i], empty[i], params, IRONWOOD_MERKLE_PARAMETERS_SIZE,
                                 empty[i + 1]).ok) return false;
    uint8_t expected[32];
    return zcl_hex_decode("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f", expected, 32) &&
        !memcmp(empty[32], expected, 32);
}
static bool one_root(const uint8_t *params, const uint8_t empty[33][32], const uint8_t leaf[32])
{
    uint8_t node[32], expected[32]; memcpy(node, leaf, 32);
    for (unsigned i = 0; i < 32; ++i)
        if (!ironwood_merkle_crh(i, node, empty[i], params, IRONWOOD_MERKLE_PARAMETERS_SIZE, node).ok) return false;
    return zcl_hex_decode("ba3699744f9a51d60cead29b609ac37d73e269864e08e79e2aedaca67c809608", expected, 32) &&
        !memcmp(node, expected, 32);
}
static bool two_root(const uint8_t *params, const uint8_t empty[33][32], const uint8_t first[32],
                     const uint8_t second[32])
{
    uint8_t node[32], expected[32];
    if (!ironwood_merkle_crh(0, first, second, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, node).ok) return false;
    for (unsigned i = 1; i < 32; ++i)
        if (!ironwood_merkle_crh(i, node, empty[i], params, IRONWOOD_MERKLE_PARAMETERS_SIZE, node).ok) return false;
    return zcl_hex_decode("382ccad224a7e382b6e18d38beb6f518ef9a30ea0a0cc259aa9021737d41cf22", expected, 32) &&
        !memcmp(node, expected, 32);
}
static bool rejects(uint8_t *params, const uint8_t leaf[32])
{
    uint8_t out[32], before[32], bad[32];
    memset(out, 0xa5, 32); memcpy(before, out, 32); memset(bad, 0xff, 32);
    if (ironwood_merkle_crh(0, bad, leaf, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, out).ok ||
        ironwood_merkle_crh(32, leaf, leaf, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, out).ok ||
        ironwood_merkle_crh(0, leaf, leaf, params, IRONWOOD_MERKLE_PARAMETERS_SIZE - 1, out).ok ||
        memcmp(out, before, 32)) return false;
    params[32] ^= 1;
    bool ok = !ironwood_merkle_parameters_valid(params, IRONWOOD_MERKLE_PARAMETERS_SIZE) &&
        !ironwood_merkle_parameters_valid(NULL, IRONWOOD_MERKLE_PARAMETERS_SIZE) &&
        !ironwood_merkle_parameters_valid(params, IRONWOOD_MERKLE_PARAMETERS_SIZE - 1) &&
        !ironwood_merkle_crh(0, leaf, leaf, params, IRONWOOD_MERKLE_PARAMETERS_SIZE, out).ok &&
        !memcmp(out, before, 32);
    params[32] ^= 1;
    return ok;
}
int test_ironwood_merkle_crh(void)
{
    uint8_t params[IRONWOOD_MERKLE_PARAMETERS_SIZE], empty[33][32], first[32], second[32];
    FILE *f = fopen("tests/fixtures/ironwood/sinsemilla-merkle-parameters.bin", "rb");
    if (!f) return 1;
    bool ok = fread(params, 1, sizeof params, f) == sizeof params && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0 || !ok) return 1;
    ok = ironwood_merkle_parameters_valid(params, sizeof params) &&
        zcl_hex_decode("7bd7041a794980ac3d8c413946d9a58e2b70de01ad27bfe18959f63d90e2b31a", first, 32) &&
        zcl_hex_decode("72d98fa009f5a73de8e05e9e25744cf6518f503881b1ed4056ae4fe176120f04", second, 32) &&
        empty_roots(params, empty) && one_root(params, empty, first) && two_root(params, empty, first, second) &&
        rejects(params, first);
    printf("Ironwood MerkleCRH: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
