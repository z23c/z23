/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Zcash note types — Sprout and Sapling. */

#ifndef ZCL_SAPLING_NOTE_H
#define ZCL_SAPLING_NOTE_H

#include "core/uint256.h"
#include "sapling/constants.h"
#include "sapling/address.h"
#include <stdbool.h>
#include <stdint.h>

struct sprout_note {
    struct uint256 a_pk;
    uint64_t value;
    struct uint256 rho;
    struct uint256 r;
};

struct sapling_note {
    unsigned char d[ZC_DIVERSIFIER_SIZE];
    struct uint256 pk_d;
    uint64_t value;
    struct uint256 r;
};

struct sprout_note_plaintext {
    uint64_t value;
    struct uint256 rho;
    struct uint256 r;
    unsigned char memo[ZC_MEMO_SIZE];
};

struct sapling_note_plaintext {
    unsigned char d[ZC_DIVERSIFIER_SIZE];
    uint64_t value;
    struct uint256 rcm;
    unsigned char memo[ZC_MEMO_SIZE];
};

struct sapling_outgoing_plaintext {
    struct uint256 pk_d;
    struct uint256 esk;
};

/* Sprout note commitment: cm = SHA256(0xb0 || a_pk || value_LE(8) || rho || r).
 * This is the leaf appended to the Sprout (SHA256Compress) commitment tree.
 * The leading 0xb0 byte is the Sprout note-commitment domain tag. */
void sprout_note_cm(const struct sprout_note *note, struct uint256 *out);

/* Sprout nullifier: nf = PRF_nf(a_sk, rho) = SHA256Compress over a_sk||rho
 * with the nf control bits. The note's rho (set when the note was created)
 * binds the nullifier, so spending the same note always yields the same nf —
 * that is what double-spend detection keys on. Requires the SPENDING key
 * a_sk (only the owner can compute it). */
void sprout_note_nullifier(const struct sprout_note *note,
                            const struct sprout_spending_key *a_sk,
                            struct uint256 *out);

/* Note-plaintext (de)serialization — this is the layout that lives inside
 * the AEAD enc_ciphertext. A 1-byte leading TYPE TAG disambiguates the pool
 * and is enforced on read: 0x00 = Sprout, 0x01 = Sapling. deserialize
 * returns false (and logs) on a wrong leading byte or a truncated stream, so
 * decrypting with the wrong pool's parser fails cleanly. All multi-byte
 * integers are little-endian. */
struct byte_stream;
bool sprout_note_plaintext_serialize(const struct sprout_note_plaintext *np,
                                      struct byte_stream *s);
bool sprout_note_plaintext_deserialize(struct sprout_note_plaintext *np,
                                        struct byte_stream *s);
bool sapling_note_plaintext_serialize(const struct sapling_note_plaintext *np,
                                       struct byte_stream *s);
bool sapling_note_plaintext_deserialize(struct sapling_note_plaintext *np,
                                         struct byte_stream *s);

#endif
