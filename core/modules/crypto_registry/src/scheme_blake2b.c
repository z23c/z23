/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "crypto_registry/crypto_registry.h"
#include "crypto/blake2b.h"

static int registry_blake2b_256(const void *data, size_t len, uint8_t out[32])
{
    if (!out)
        return -1;
    return blake2b(out, 32, data, len, NULL, 0);
}

static const struct crypto_scheme g_blake2b_scheme = {
    .id = CRYPTO_HASH_BLAKE2B_256,
    .kind = CRYPTO_KIND_HASH,
    .status = CRYPTO_STATUS_ACTIVE,
    .name = "blake2b-256",
    .impl = "in-tree core/modules/crypto/src/blake2b.c",
    .fn.hash = registry_blake2b_256,
};

__attribute__((constructor))
static void register_blake2b_scheme(void)
{
    crypto_registry_register(&g_blake2b_scheme);
}
