/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Zcash shielded address types — Sprout and Sapling. */

#include "sapling/address.h"
#include "sapling/prf.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "support/cleanse.h"
#include <string.h>

void sprout_payment_address_get_hash(const struct sprout_payment_address *addr,
                                      struct uint256 *out)
{
    struct byte_stream s;
    stream_init(&s, 64);
    sprout_payment_address_serialize(addr, &s);
    hash256(s.data, s.size, out->data);
    stream_free(&s);
}

void sapling_payment_address_get_hash(const struct sapling_payment_address *addr,
                                       struct uint256 *out)
{
    struct byte_stream s;
    stream_init(&s, 64);
    sapling_payment_address_serialize(addr, &s);
    hash256(s.data, s.size, out->data);
    stream_free(&s);
}

void sprout_spending_key_to_viewing_key(const struct sprout_spending_key *sk,
                                         struct sprout_viewing_key *vk)
{
    prf_addr_a_pk(sk->data, &vk->a_pk);

    /* sk_enc = receiving_key = ZCNoteEncryption::generate_privkey(a_sk)
     * This is PRF_addr_sk_enc(a_sk) = SHA256Compress(a_sk || 01...) with
     * control bits [0..3] = 0100 (first nibble = 0x?0, second = 0x?1).
     * Then clamp the result to a valid Curve25519 scalar. */
    prf_addr_sk_enc(sk->data, &vk->sk_enc);

    /* Clamp: clear low 3 bits and high bit, set second-highest bit.
     * This matches Curve25519 clamping for NoteEncryption. */
    vk->sk_enc.data[0] &= 248;
    vk->sk_enc.data[31] &= 127;
    vk->sk_enc.data[31] |= 64;
}

void sprout_viewing_key_to_address(const struct sprout_viewing_key *vk,
                                    struct sprout_payment_address *addr)
{
    addr->a_pk = vk->a_pk;
    /* pk_enc = crypto_scalarmult_base(sk_enc) — Curve25519 base point multiply.
     * This requires Curve25519 which we don't have yet, so for now we store
     * the viewing key's a_pk and leave pk_enc zeroed. Full implementation
     * needs Curve25519 scalar multiplication. */
    memset(addr->pk_enc.data, 0, 32);
}

void sprout_spending_key_to_address(const struct sprout_spending_key *sk,
                                     struct sprout_payment_address *addr)
{
    struct sprout_viewing_key vk;
    sprout_spending_key_to_viewing_key(sk, &vk);
    sprout_viewing_key_to_address(&vk, addr);
    memory_cleanse(&vk, sizeof(vk));
}

void sapling_spending_key_to_expanded(const struct sapling_spending_key *sk,
                                       struct sapling_expanded_spending_key *esk)
{
    prf_ask(&sk->sk, &esk->ask);
    prf_nsk(&sk->sk, &esk->nsk);
    prf_ovk(&sk->sk, &esk->ovk);
}

bool sprout_payment_address_serialize(const struct sprout_payment_address *addr,
                                       struct byte_stream *s)
{
    return stream_write_bytes(s, addr->a_pk.data, 32) &&
           stream_write_bytes(s, addr->pk_enc.data, 32);
}

bool sprout_payment_address_deserialize(struct sprout_payment_address *addr,
                                         struct byte_stream *s)
{
    return stream_read_bytes(s, addr->a_pk.data, 32) &&
           stream_read_bytes(s, addr->pk_enc.data, 32);
}

bool sapling_payment_address_serialize(const struct sapling_payment_address *addr,
                                        struct byte_stream *s)
{
    return stream_write_bytes(s, addr->d, ZC_DIVERSIFIER_SIZE) &&
           stream_write_bytes(s, addr->pk_d.data, 32);
}

bool sapling_payment_address_deserialize(struct sapling_payment_address *addr,
                                          struct byte_stream *s)
{
    return stream_read_bytes(s, addr->d, ZC_DIVERSIFIER_SIZE) &&
           stream_read_bytes(s, addr->pk_d.data, 32);
}
