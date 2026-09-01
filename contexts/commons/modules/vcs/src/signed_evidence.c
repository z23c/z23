/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Stateless domain-rooted signatures shared by VCS evidence codecs. */

#include "vcs/signed_evidence.h"

#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

bool vcs_signed_evidence_root(const char *domain, size_t domain_len,
                              const uint8_t *body, size_t body_len,
                              uint8_t out[32])
{
    if (!domain || domain_len == 0 || (!body && body_len != 0) || !out)
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    if (body_len != 0) sha3_256_write(&sha, body, body_len);
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_signed_evidence_seal_root(const uint8_t root[32],
                                   const uint8_t secret[32],
                                   const uint8_t pubkey[32],
                                   uint8_t signature[64])
{
    if (!root || !secret || !pubkey || !signature) return false;
    ed25519_sign(signature, root, 32, secret, pubkey);
    return true;
}

bool vcs_signed_evidence_verify_root(const uint8_t root[32],
                                     const uint8_t signature[64],
                                     const uint8_t signer_pubkey[32],
                                     const uint8_t expected_signer[32])
{
    return root && signature && signer_pubkey && expected_signer &&
           memcmp(signer_pubkey, expected_signer, 32) == 0 &&
           ed25519_verify(signature, root, 32, signer_pubkey);
}
