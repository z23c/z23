/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_PUBKEY_H
#define ZCL_PUBKEY_H

#include "core/hash.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define PUBLIC_KEY_SIZE 65
#define COMPRESSED_PUBLIC_KEY_SIZE 33
#define SIGNATURE_SIZE 72
#define COMPACT_SIGNATURE_SIZE 65
#define BIP32_EXTKEY_SIZE 74

struct key_id {
    struct uint160 id;
};

struct pubkey {
    unsigned char vch[PUBLIC_KEY_SIZE];
    unsigned int size;
};

struct ext_pubkey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    struct uint256 chaincode;
    struct pubkey pubkey;
};

static inline void pubkey_init(struct pubkey *pk)
{
    memset(pk, 0, sizeof(*pk));
}

static inline bool pubkey_is_valid(const struct pubkey *pk)
{
    return pk->size > 0;
}

static inline bool pubkey_is_compressed(const struct pubkey *pk)
{
    return pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static inline void pubkey_set(struct pubkey *pk,
                              const unsigned char *data, unsigned int len)
{
    if (len > PUBLIC_KEY_SIZE) len = PUBLIC_KEY_SIZE;
    memcpy(pk->vch, data, len);
    pk->size = len;
}

static inline struct key_id pubkey_get_id(const struct pubkey *pk)
{
    struct key_id kid;
    hash160(pk->vch, pk->size, kid.id.data);
    return kid;
}

/* ECDSA/secp256k1 verification routes through crypto_registry so the
 * script-validation hot path uses the same scheme indirection as other
 * consensus crypto. */
bool pubkey_verify(const struct pubkey *pk, const struct uint256 *hash,
                   const unsigned char *sig, size_t siglen);

/* Recover the public key that signed hash from a 65-byte compact recoverable
 * signature (as produced by privkey_sign_compact), writing it into pk with the
 * compression encoded in the header byte. Returns false if the signature does
 * not parse or no key recovers. */
bool pubkey_recover_compact(struct pubkey *pk, const struct uint256 *hash,
                            const unsigned char sig[COMPACT_SIGNATURE_SIZE]);

/* True only if pk is a well-formed point on secp256k1 (stricter than
 * pubkey_is_valid, which merely checks the stored length is non-zero). */
bool pubkey_is_fully_valid(const struct pubkey *pk);

/* Re-serialize pk in uncompressed form in place. Returns false if pk is empty
 * or does not parse as a valid curve point. */
bool pubkey_decompress(struct pubkey *pk);

/* BIP32 non-hardened public child derivation: produce child and its chaincode
 * from parent pk, chaincode cc, and non-hardened index nChild. Total on
 * hostile input: returns false (never aborts) if pk is empty, if pk is not a
 * 33-byte compressed key, if nChild is hardened (bit 31 set), or if parsing
 * or the EC point tweak fails. */
bool pubkey_derive(const struct pubkey *pk, struct pubkey *child,
                   struct uint256 *cc_child, unsigned int nChild,
                   const struct uint256 *cc);

/* True if the DER signature parses and its s value is already in the canonical
 * low-S half-order range (BIP62 malleability rule). */
bool pubkey_check_low_s(const unsigned char *sig, size_t siglen);

/* Serialize / parse the 74-byte BIP32 extended-public-key body (depth, parent
 * fingerprint, child index, chaincode, and the 33-byte compressed key).
 * ext_pubkey_encode returns false (it does not abort) if epk does not hold a
 * 33-byte compressed key, leaving code[] untouched. */
bool ext_pubkey_encode(const struct ext_pubkey *epk,
                       unsigned char code[BIP32_EXTKEY_SIZE]);
void ext_pubkey_decode(struct ext_pubkey *epk,
                       const unsigned char code[BIP32_EXTKEY_SIZE]);
/* Derive the nChild extended public child of epk (incrementing depth and
 * stamping the parent fingerprint). Returns false on a derivation failure;
 * only non-hardened indices are derivable from a public key. */
bool ext_pubkey_derive(const struct ext_pubkey *epk,
                       struct ext_pubkey *out, unsigned int nChild);

/* Create / destroy the process-wide secp256k1 verification context. Call
 * ecc_verify_init once at startup before any pubkey verify/recover/parse. */
void ecc_verify_init(void);
bool ecc_verify_init_once(void);
void ecc_verify_destroy(void);

#endif
