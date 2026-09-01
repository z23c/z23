/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "crypto_registry/crypto_registry.h"
#include "keys/pubkey.h"

#include <secp256k1.h>
#include <string.h>

static secp256k1_context *g_verify_ctx;

static bool registry_ecdsa_verify(const uint8_t *pubkey, size_t pubkey_len,
                                  const uint8_t *msg, size_t msg_len,
                                  const uint8_t *sig, size_t sig_len)
{
    if (!pubkey || !msg || !sig || msg_len != 32 ||
        pubkey_len > PUBLIC_KEY_SIZE || pubkey_len == 0 || sig_len == 0 ||
        !g_verify_ctx)
        return false;

    secp256k1_pubkey parsed_pubkey;
    secp256k1_ecdsa_signature parsed_sig;
    if (!secp256k1_ec_pubkey_parse(g_verify_ctx, &parsed_pubkey,
                                    pubkey, pubkey_len))
        return false;
    if (!secp256k1_ecdsa_signature_parse_der(g_verify_ctx, &parsed_sig,
                                              sig, sig_len))
        return false;
    secp256k1_ecdsa_signature_normalize(g_verify_ctx, &parsed_sig,
                                         &parsed_sig);
    return secp256k1_ecdsa_verify(g_verify_ctx, &parsed_sig, msg,
                                   &parsed_pubkey);
}

static const struct crypto_scheme g_ecdsa_scheme = {
    .id = CRYPTO_SIG_ECDSA_SECP256K1,
    .kind = CRYPTO_KIND_SIG,
    .status = CRYPTO_STATUS_ACTIVE,
    .name = "ecdsa-secp256k1",
    .impl = "in-tree keys/pubkey.c over vendored libsecp256k1",
    .fn.sig_verify = registry_ecdsa_verify,
};

__attribute__((constructor))
static void register_ecdsa_scheme(void)
{
    g_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    crypto_registry_register(&g_ecdsa_scheme);
}

__attribute__((destructor))
static void destroy_ecdsa_scheme(void)
{
    if (g_verify_ctx)
        secp256k1_context_destroy(g_verify_ctx);
}
