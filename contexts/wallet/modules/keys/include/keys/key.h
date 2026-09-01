/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_KEY_H
#define ZCL_KEY_H

#include "keys/pubkey.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

#define PRIVATE_KEY_SIZE 279
#define COMPRESSED_PRIVATE_KEY_SIZE 214

struct privkey {
    unsigned char vch[32];
    bool fValid;
    bool fCompressed;
};

struct ext_key {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    struct uint256 chaincode;
    struct privkey key;
};

static inline void privkey_init(struct privkey *k)
{
    memset(k, 0, sizeof(*k));
}

static inline bool privkey_is_valid(const struct privkey *k)
{
    return k->fValid;
}

static inline bool privkey_is_compressed(const struct privkey *k)
{
    return k->fCompressed;
}

/* Draw a fresh, secp256k1-valid private key into k, marking it valid and
 * setting its compression flag. Aborts the process if the secure RNG fails. */
void privkey_make_new(struct privkey *k, bool fCompressed);
/* Derive the secp256k1 public key for k, honoring k's compression flag.
 * Returns false (never aborts) if k is invalid or its scalar is out of
 * range [1, n-1] — externally-sourced WIFs reach this via importprivkey/
 * signrawtransaction, so an attacker-supplied scalar must not be able to
 * abort the node. */
bool privkey_get_pubkey(const struct privkey *k, struct pubkey *pk);
/* Range-validate an externally-sourced scalar: true iff 0 < vch < the
 * secp256k1 group order. fValid alone means "bytes were loaded", NOT
 * "scalar is a usable secret key" — boundary decoders must call this. */
bool privkey_range_check(const struct privkey *k);
/* Produce a DER-encoded ECDSA signature over the 32-byte hash using RFC6979
 * deterministic nonces. On entry *siglen is ignored; on success it holds the
 * actual DER length (<= SIGNATURE_SIZE). Returns false if k is invalid. */
bool privkey_sign(const struct privkey *k, const struct uint256 *hash,
                  unsigned char *sig, size_t *siglen);
/* Produce a 65-byte compact recoverable signature (1 header byte encoding the
 * recovery id and compression, then 64 bytes r||s). Returns false if k is
 * invalid; the buffer must be COMPACT_SIGNATURE_SIZE bytes. */
bool privkey_sign_compact(const struct privkey *k, const struct uint256 *hash,
                          unsigned char sig[COMPACT_SIGNATURE_SIZE]);
/* Self-check that pk is the public key for k: verifies the compression flags
 * agree and that a signature from k over a random challenge verifies under pk.
 * Returns false on mismatch or if the secure RNG fails. */
bool privkey_verify_pubkey(const struct privkey *k, const struct pubkey *pk);
/* BIP32 child private-key derivation: produce child key and its chaincode from
 * parent key k, parent chaincode cc, and index nChild (hardened when the high
 * bit is set). Requires (asserts) a valid, compressed parent. Returns false if
 * the resulting key is out of range (caller must retry the next index). */
bool privkey_derive(const struct privkey *k, struct privkey *child,
                    struct uint256 *cc_child, unsigned int nChild,
                    const struct uint256 *cc);

/* Serialize / parse the 74-byte BIP32 extended-private-key body (depth,
 * parent fingerprint, child index, chaincode, and the 32-byte key with its
 * leading zero pad). ext_key_decode revalidates the key against secp256k1. */
void ext_key_encode(const struct ext_key *ek,
                    unsigned char code[BIP32_EXTKEY_SIZE]);
void ext_key_decode(struct ext_key *ek,
                    const unsigned char code[BIP32_EXTKEY_SIZE]);
/* Derive the nChild extended child of ek (incrementing depth and stamping the
 * parent fingerprint). Returns false if the underlying key derivation fails. */
bool ext_key_derive(const struct ext_key *ek, struct ext_key *out,
                    unsigned int nChild);
/* Build the BIP32 master extended key from a seed via HMAC-SHA512("Bitcoin
 * seed"). The key is marked compressed; depth/child/fingerprint are zeroed.
 * The intermediate HMAC output is wiped before return. */
void ext_key_set_master(struct ext_key *ek, const unsigned char *seed,
                        unsigned int nSeedLen);
/* Neuter ek into its public-only extended counterpart (same metadata and
 * chaincode, public key in place of the private key). */
void ext_key_neuter(const struct ext_key *ek, struct ext_pubkey *epk);

/* Round-trip sanity check that signing+verification work; true on success.
 * Call after ecc_start()/ecc_verify_init() during startup self-test. */
bool ecc_init_sanity_check(void);
/* Create / destroy the process-wide secp256k1 signing context. ecc_start must
 * be called once before any signing/derivation; ecc_stop releases it. */
void ecc_start(void);
void ecc_stop(void);

/* Idempotent ecc_start for OFFLINE entry points.
 *
 * ecc_start() is boot wiring and asserts if a context already exists — the
 * right behaviour for boot, which runs it exactly once. But a CLI command
 * that does key derivation without a node (recovering a wallet from its
 * phrase, say) may be the first thing in the process to need a signing
 * context, or may be running inside a node that already started one. This
 * gives it a context either way and returns true when one is in force.
 *
 * Not thread-safe: call it from the single-threaded entry path, before any
 * worker exists. Inside a running node it only ever observes the context
 * boot already created and returns immediately. */
bool ecc_start_once(void);

#endif
