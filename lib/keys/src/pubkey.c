/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "keys/pubkey.h"
#include "crypto/common.h"
#include "crypto_registry/crypto_registry.h"
#include "util/log_macros.h"
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <stdatomic.h>

static secp256k1_context *secp256k1_ctx_verify = NULL;
static _Atomic(const struct crypto_scheme *) g_ecdsa_verify_scheme;

bool pubkey_verify(const struct pubkey *pk, const struct uint256 *hash,
                   const unsigned char *sig, size_t siglen)
{
    if (!pubkey_is_valid(pk))
        return false;
    if (!hash || !sig || siglen == 0)
        return false;

    const struct crypto_scheme *scheme = atomic_load_explicit(
        &g_ecdsa_verify_scheme, memory_order_relaxed);
    if (!scheme) {
        scheme = crypto_registry_lookup(CRYPTO_SIG_ECDSA_SECP256K1);
        atomic_store_explicit(&g_ecdsa_verify_scheme, scheme,
                              memory_order_relaxed);
    }
    if (!scheme || !scheme->fn.sig_verify) {
        LOG_FAIL("crypto_registry", "ecdsa-secp256k1 scheme unavailable");
        return false;
    }

    return scheme->fn.sig_verify(pk->vch, pk->size, hash->data,
                                 sizeof(hash->data), sig, siglen);
}

bool pubkey_recover_compact(struct pubkey *pk, const struct uint256 *hash,
                            const unsigned char sig[COMPACT_SIGNATURE_SIZE])
{
    int recid = (sig[0] - 27) & 3;
    bool fComp = ((sig[0] - 27) & 4) != 0;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_ctx_verify, &rsig, &sig[1], recid))
        return false;
    if (!secp256k1_ecdsa_recover(secp256k1_ctx_verify, &pubkey, &rsig,
                                  hash->data))
        return false;
    unsigned char pub[PUBLIC_KEY_SIZE];
    size_t publen = PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_verify, pub, &publen, &pubkey,
        fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    pubkey_set(pk, pub, (unsigned int)publen);
    return true;
}

bool pubkey_is_fully_valid(const struct pubkey *pk)
{
    if (!pubkey_is_valid(pk))
        return false;
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(secp256k1_ctx_verify, &pubkey,
                                      pk->vch, pk->size);
}

bool pubkey_decompress(struct pubkey *pk)
{
    if (!pubkey_is_valid(pk))
        return false;
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_verify, &pubkey,
                                    pk->vch, pk->size))
        return false;
    unsigned char pub[PUBLIC_KEY_SIZE];
    size_t publen = PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_verify, pub, &publen, &pubkey,
                                   SECP256K1_EC_UNCOMPRESSED);
    pubkey_set(pk, pub, (unsigned int)publen);
    return true;
}

bool pubkey_derive(const struct pubkey *pk, struct pubkey *child,
                   struct uint256 *cc_child, unsigned int nChild,
                   const struct uint256 *cc)
{
    /* Total function on purpose: BIP32 derivation is reachable from
     * watch-only xpub import and wallet address scanning, both of which
     * carry externally-supplied parent keys and child indices. assert() is
     * live in release builds (-DNDEBUG is not set for the node), so the old
     * assert() trio let one bad xpub or one hardened index abort the whole
     * node. All three now fail cleanly to the caller. */
    if (!pubkey_is_valid(pk))
        LOG_FAIL("keys", "pubkey_derive: parent key is empty");
    if ((nChild >> 31) != 0)
        LOG_FAIL("keys", "pubkey_derive: index %u is hardened; hardened "
                 "children cannot be derived from a public key", nChild);
    if (pk->size != COMPRESSED_PUBLIC_KEY_SIZE)
        LOG_FAIL("keys", "pubkey_derive: parent key is %u bytes, BIP32 "
                 "requires a %d-byte compressed key",
                 pk->size, COMPRESSED_PUBLIC_KEY_SIZE);
    unsigned char out[64];
    bip32_hash(cc->data, nChild, pk->vch[0], pk->vch + 1, out);
    memcpy(cc_child->data, out + 32, 32);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_verify, &pubkey,
                                    pk->vch, pk->size))
        return false;
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_verify, &pubkey, out))
        return false;
    unsigned char pub[COMPRESSED_PUBLIC_KEY_SIZE];
    size_t publen = COMPRESSED_PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_verify, pub, &publen, &pubkey,
                                   SECP256K1_EC_COMPRESSED);
    pubkey_set(child, pub, (unsigned int)publen);
    return true;
}

bool pubkey_check_low_s(const unsigned char *sig, size_t siglen)
{
    secp256k1_ecdsa_signature esig;
    if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx_verify, &esig,
                                              sig, siglen))
        return false;
    return !secp256k1_ecdsa_signature_normalize(secp256k1_ctx_verify,
                                                 NULL, &esig);
}

/* Returns false (instead of the old live assert()) when the extended key
 * does not hold a compressed public key: hd_serialize_xpub feeds this from
 * wallet state that an uncompressed or empty key can reach, and the
 * fixed-width BIP32 body has no encoding for anything else. */
bool ext_pubkey_encode(const struct ext_pubkey *epk,
                       unsigned char code[BIP32_EXTKEY_SIZE])
{
    if (epk->pubkey.size != COMPRESSED_PUBLIC_KEY_SIZE)
        LOG_FAIL("keys", "ext_pubkey_encode: key is %u bytes, the BIP32 "
                 "extended-key body holds only a %d-byte compressed key",
                 epk->pubkey.size, COMPRESSED_PUBLIC_KEY_SIZE);
    code[0] = epk->nDepth;
    memcpy(code + 1, epk->vchFingerprint, 4);
    WriteBE32(code + 5, epk->nChild);
    memcpy(code + 9, epk->chaincode.data, 32);
    memcpy(code + 41, epk->pubkey.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    return true;
}

void ext_pubkey_decode(struct ext_pubkey *epk,
                       const unsigned char code[BIP32_EXTKEY_SIZE])
{
    epk->nDepth = code[0];
    memcpy(epk->vchFingerprint, code + 1, 4);
    epk->nChild = ReadBE32(code + 5);
    memcpy(epk->chaincode.data, code + 9, 32);
    pubkey_set(&epk->pubkey, code + 41, COMPRESSED_PUBLIC_KEY_SIZE);
}

bool ext_pubkey_derive(const struct ext_pubkey *epk,
                       struct ext_pubkey *out, unsigned int nChild)
{
    out->nDepth = epk->nDepth + 1;
    struct key_id id = pubkey_get_id(&epk->pubkey);
    memcpy(out->vchFingerprint, id.id.data, 4);
    out->nChild = nChild;
    return pubkey_derive(&epk->pubkey, &out->pubkey, &out->chaincode,
                         nChild, &epk->chaincode);
}

/* The asserts in these two are DELIBERATELY left as asserts. Unlike every
 * other check in this file they guard a process-wide singleton's lifecycle,
 * not caller-supplied data: no external input can reach them, both are
 * called exactly once (startup / shutdown), and a violation means the boot
 * sequence itself is wired wrong. Failing loudly at that point is correct —
 * a node that carries on with a NULL or double-created verification context
 * would silently accept or reject signatures. */
void ecc_verify_init(void)
{
    assert(secp256k1_ctx_verify == NULL); // abort-ok: boot wiring, double init would leak the live verification context
    secp256k1_ctx_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    assert(secp256k1_ctx_verify != NULL); // abort-ok: without a verification context every signature check is meaningless
}

bool ecc_verify_init_once(void)
{
    if (secp256k1_ctx_verify)
        return true;
    ecc_verify_init();
    return secp256k1_ctx_verify != NULL;
}

void ecc_verify_destroy(void)
{
    assert(secp256k1_ctx_verify != NULL); // abort-ok: shutdown ordering violation, the context was already torn down
    secp256k1_context_destroy(secp256k1_ctx_verify);
    secp256k1_ctx_verify = NULL;
}
