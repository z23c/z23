/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "keys/key.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "crypto/random_secret.h"
#include "core/hash.h"
#include "core/random.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <stdlib.h>

/* secp256k1_ec_seckey_tweak_add shim is in secp256k1_compat.c */

static secp256k1_context *secp256k1_ctx_sign = NULL;

void privkey_make_new(struct privkey *k, bool fCompressed)
{
    do {
        if (!zcl_random_secret_bytes(k->vch, 32, "secp256k1_privkey"))
            abort(); // abort-ok: no entropy; wrapper logged, void return blocks propagation, and continuing hands out a guessable key
    } while (!secp256k1_ec_seckey_verify(secp256k1_ctx_sign, k->vch));
    k->fValid = true;
    k->fCompressed = fCompressed;
}

bool privkey_range_check(const struct privkey *k)
{
    return k && secp256k1_ec_seckey_verify(secp256k1_ctx_sign, k->vch);
}

/* These three are total functions on purpose: externally-sourced WIFs
 * (importprivkey, signrawtransaction privkeys[]) reach them, and
 * secp256k1 returns 0 for a scalar that is 0 or >= the group order.
 * assert() is live in release builds (-DNDEBUG is not set), so the old
 * assert(ret) pattern let one hostile RPC parameter abort the whole
 * node. Out-of-range scalars now fail cleanly to the caller. */
bool privkey_get_pubkey(const struct privkey *k, struct pubkey *pk)
{
    pubkey_init(pk); /* defined (invalid) output even on the failure paths */
    if (!k->fValid)
        return false;
    secp256k1_pubkey pubkey;
    size_t clen = PUBLIC_KEY_SIZE;
    unsigned char buf[PUBLIC_KEY_SIZE];
    int ret = secp256k1_ec_pubkey_create(secp256k1_ctx_sign, &pubkey, k->vch);
    if (!ret)
        return false;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_sign, buf, &clen, &pubkey,
        k->fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    pubkey_set(pk, buf, (unsigned int)clen);
    return true;
}

bool privkey_sign(const struct privkey *k, const struct uint256 *hash,
                  unsigned char *sig, size_t *siglen)
{
    if (!k->fValid) return false;
    *siglen = SIGNATURE_SIZE;
    secp256k1_ecdsa_signature esig;
    int ret = secp256k1_ecdsa_sign(secp256k1_ctx_sign, &esig, hash->data,
                                    k->vch, secp256k1_nonce_function_rfc6979,
                                    NULL);
    if (!ret)
        return false;
    secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx_sign, sig,
                                             siglen, &esig);
    return true;
}

bool privkey_sign_compact(const struct privkey *k, const struct uint256 *hash,
                          unsigned char sig[COMPACT_SIGNATURE_SIZE])
{
    if (!k->fValid) return false;
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature rsig;
    int ret = secp256k1_ecdsa_sign_recoverable(secp256k1_ctx_sign, &rsig,
        hash->data, k->vch, secp256k1_nonce_function_rfc6979, NULL);
    if (!ret)
        return false;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        secp256k1_ctx_sign, sig + 1, &rec, &rsig);
    if (rec == -1)
        return false;
    sig[0] = (unsigned char)(27 + rec + (k->fCompressed ? 4 : 0));
    return true;
}

bool privkey_verify_pubkey(const struct privkey *k, const struct pubkey *pk)
{
    if (pubkey_is_compressed(pk) != k->fCompressed)
        return false;
    unsigned char rnd[8];
    if (!zcl_random_secret_bytes(rnd, sizeof(rnd), "privkey_verify_nonce"))
        return false;
    const char *str = "Zclassic key verification\n";
    size_t str_len = 26;
    struct sha256_ctx hasher;
    sha256_init(&hasher);
    sha256_write(&hasher, (const unsigned char *)str, str_len);
    sha256_write(&hasher, rnd, sizeof(rnd));
    unsigned char tmp[32];
    sha256_finalize(&hasher, tmp);
    struct sha256_ctx hasher2;
    sha256_init(&hasher2);
    sha256_write(&hasher2, tmp, 32);
    struct uint256 hash;
    sha256_finalize(&hasher2, hash.data);

    unsigned char sig[SIGNATURE_SIZE];
    size_t siglen = SIGNATURE_SIZE;
    privkey_sign(k, &hash, sig, &siglen);
    return pubkey_verify(pk, &hash, sig, siglen);
}

bool privkey_derive(const struct privkey *k, struct privkey *child,
                    struct uint256 *cc_child, unsigned int nChild,
                    const struct uint256 *cc)
{
    assert(k->fValid && k->fCompressed);
    unsigned char out[64];
    if ((nChild >> 31) == 0) {
        struct pubkey pk;
        privkey_get_pubkey(k, &pk);
        assert(pk.size == COMPRESSED_PUBLIC_KEY_SIZE);
        bip32_hash(cc->data, nChild, pk.vch[0], pk.vch + 1, out);
    } else {
        bip32_hash(cc->data, nChild, 0, k->vch, out);
    }
    memcpy(cc_child->data, out + 32, 32);
    memcpy(child->vch, k->vch, 32);
    bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_ctx_sign,
                                               child->vch, out);
    child->fCompressed = true;
    child->fValid = ret;
    /* out[0..31] was tweaked into the child EC scalar — wipe the HMAC output so
     * raw key material does not linger on the stack (the memset+barrier defeats
     * dead-store elimination). Mirrors ext_key_set_master's cleanse. */
    memory_cleanse(out, sizeof(out));
    return ret;
}

void ext_key_encode(const struct ext_key *ek,
                    unsigned char code[BIP32_EXTKEY_SIZE])
{
    code[0] = ek->nDepth;
    memcpy(code + 1, ek->vchFingerprint, 4);
    WriteBE32(code + 5, ek->nChild);
    memcpy(code + 9, ek->chaincode.data, 32);
    code[41] = 0;
    memcpy(code + 42, ek->key.vch, 32);
}

void ext_key_decode(struct ext_key *ek,
                    const unsigned char code[BIP32_EXTKEY_SIZE])
{
    ek->nDepth = code[0];
    memcpy(ek->vchFingerprint, code + 1, 4);
    ek->nChild = ReadBE32(code + 5);
    memcpy(ek->chaincode.data, code + 9, 32);
    memcpy(ek->key.vch, code + 42, 32);
    ek->key.fValid = secp256k1_ec_seckey_verify(secp256k1_ctx_sign, ek->key.vch);
    ek->key.fCompressed = true;
}

bool ext_key_derive(const struct ext_key *ek, struct ext_key *out,
                    unsigned int nChild)
{
    out->nDepth = ek->nDepth + 1;
    struct pubkey pk;
    privkey_get_pubkey(&ek->key, &pk);
    struct key_id id = pubkey_get_id(&pk);
    memcpy(out->vchFingerprint, id.id.data, 4);
    out->nChild = nChild;
    return privkey_derive(&ek->key, &out->key, &out->chaincode,
                          nChild, &ek->chaincode);
}

void ext_key_set_master(struct ext_key *ek, const unsigned char *seed,
                        unsigned int nSeedLen)
{
    static const unsigned char hashkey[] = {
        'B','i','t','c','o','i','n',' ','s','e','e','d'
    };
    unsigned char out[64];
    struct hmac_sha512_ctx hmac;
    hmac_sha512_init(&hmac, hashkey, sizeof(hashkey));
    hmac_sha512_write(&hmac, seed, nSeedLen);
    hmac_sha512_finalize(&hmac, out);
    memcpy(ek->key.vch, out, 32);
    ek->key.fValid = secp256k1_ec_seckey_verify(secp256k1_ctx_sign, ek->key.vch);
    ek->key.fCompressed = true;
    memcpy(ek->chaincode.data, out + 32, 32);
    ek->nDepth = 0;
    ek->nChild = 0;
    memset(ek->vchFingerprint, 0, sizeof(ek->vchFingerprint));
    memset(out, 0, sizeof(out));
}

void ext_key_neuter(const struct ext_key *ek, struct ext_pubkey *epk)
{
    epk->nDepth = ek->nDepth;
    memcpy(epk->vchFingerprint, ek->vchFingerprint, 4);
    epk->nChild = ek->nChild;
    privkey_get_pubkey(&ek->key, &epk->pubkey);
    epk->chaincode = ek->chaincode;
}

bool ecc_init_sanity_check(void)
{
    struct privkey k;
    privkey_make_new(&k, true);
    struct pubkey pk;
    privkey_get_pubkey(&k, &pk);
    return privkey_verify_pubkey(&k, &pk);
}

/* The assertions in ecc_start guard the process-wide SIGNING context's
 * lifecycle, not caller-supplied data — the same reasoning as
 * ecc_verify_init/ecc_verify_destroy in pubkey.c. No external input reaches
 * them, ecc_start runs exactly once at boot, and a node that carried on past
 * a NULL or double-created context would sign with an unrandomized context
 * or not at all. Failing loudly here is correct. */
void ecc_start(void)
{
    assert(secp256k1_ctx_sign == NULL); // abort-ok: boot wiring, double ecc_start would leak the live signing context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != NULL); // abort-ok: no signing context means no signature this node produces can be trusted
    unsigned char seed[32];
    if (!zcl_random_secret_bytes(seed, 32, "secp256k1_ctx_randomize"))
        abort(); // abort-ok: no entropy; wrapper logged, void return blocks propagation, and an unblinded context leaks key material via side channels
    bool ret = secp256k1_context_randomize(ctx, seed);
    assert(ret); // abort-ok: unrandomized signing context, side-channel blinding is not in force
    memset(seed, 0, sizeof(seed));
    secp256k1_ctx_sign = ctx;
}

bool ecc_start_once(void)
{
    if (secp256k1_ctx_sign)
        return true;
    ecc_start();
    return secp256k1_ctx_sign != NULL;
}

void ecc_stop(void)
{
    secp256k1_context *ctx = secp256k1_ctx_sign;
    secp256k1_ctx_sign = NULL;
    if (ctx)
        secp256k1_context_destroy(ctx);
}
