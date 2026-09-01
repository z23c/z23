/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "crypto_registry/crypto_registry.h"
#include "crypto/sha256.h"

static int registry_sha256(const void *data, size_t len, uint8_t out[32])
{
    if (!out)
        return -1;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, out);
    return 0;
}

static const struct crypto_scheme g_sha256_scheme = {
    .id = CRYPTO_HASH_SHA256,
    .kind = CRYPTO_KIND_HASH,
    .status = CRYPTO_STATUS_ACTIVE,
    .name = "sha256",
    .impl = "in-tree core/modules/crypto/src/sha256.c",
    .fn.hash = registry_sha256,
};

__attribute__((constructor))
static void register_sha256_scheme(void)
{
    crypto_registry_register(&g_sha256_scheme);
}
