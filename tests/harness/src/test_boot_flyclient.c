/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_flyclient.h"

#include <stdint.h>
#include <stdio.h>

#define BFC_CHECK(name, expr) do {                                      \
    printf("boot_flyclient: %s... ", (name));                         \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

int test_boot_flyclient(void)
{
    int failures = 0;
    uint8_t hash_out[1][32];
    uint8_t sha3[32];
    uint64_t count = 0;

    BFC_CHECK("proof builder rejects missing args",
              !boot_build_flyclient_proof(NULL, NULL, NULL, NULL));

    BFC_CHECK("block hash loader rejects missing context",
              boot_load_block_hashes_range(0, 1, hash_out, 1, NULL) == 0);

    BFC_CHECK("block hash loader rejects missing output",
              boot_load_block_hashes_range(0, 1, NULL, 1, NULL) == 0);

    BFC_CHECK("utxo sha3 provider rejects missing context",
              !boot_compute_utxo_sha3(sha3, &count, NULL));

    BFC_CHECK("utxo snapshot serializer rejects missing db",
              boot_serialize_utxo_snapshot(NULL, "/tmp/nope", 500,
                                           sha3) == -1);

    BFC_CHECK("mmb leaf store prepare rejects missing service",
              !boot_prepare_mmb_leaf_store(NULL, "/tmp", NULL));

    return failures;
}
