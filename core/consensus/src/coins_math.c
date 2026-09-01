/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton
 *
 * Pure UTXO/coins arithmetic. Replays from inputs alone — no clock,
 * no RNG, no allocation, no I/O, no view/cache reads. Extracted from
 * core/modules/coins/src/{coins,compressor}.c and the pure slice of
 * core/modules/validation/src/update_coins.c (the "capture undo for one
 * already-resolved coin" portion). The lib/ wrappers are now thin
 * forwarders.
 *
 * See the header for the exact contract of each function and the
 * rationale for what stayed in lib/. */

#include "domain/consensus/coins_math.h"

#include <string.h>

#include "coins/coins.h"
#include "coins/undo.h"
#include "keys/pubkey.h"
#include "primitives/transaction.h"
#include "script/script.h"

/* ── Pure predicates / mutators on a single `struct coins` ────────── */

bool coins_math_is_pruned(const struct coins *c)
{
    if (!c)
        return true;
    for (size_t i = 0; i < c->num_vout; i++) {
        if (!tx_out_is_null(&c->vout[i]))
            return false;
    }
    return true;
}

bool coins_math_is_available(const struct coins *c, unsigned int pos)
{
    if (!c)
        return false;
    return pos < c->num_vout && !tx_out_is_null(&c->vout[pos]);
}

bool coins_math_spend(struct coins *c, uint32_t pos)
{
    if (!c)
        return false;
    if (pos >= c->num_vout || tx_out_is_null(&c->vout[pos]))
        return false;
    tx_out_set_null(&c->vout[pos]);
    /* Deliberately NO cleanup() call here — see header / legacy
     * coins_spend() comment. Trimming on spend would break a
     * subsequent disconnect that restores a higher vout index. */
    return true;
}

void coins_math_cleanup(struct coins *c)
{
    if (!c)
        return;
    while (c->num_vout > 0 && tx_out_is_null(&c->vout[c->num_vout - 1]))
        c->num_vout--;
}

struct zcl_result coins_math_capture_undo(
        struct coins *c, uint32_t pos, struct tx_in_undo *undo)
{
    if (!c)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINS_MATH_ERR_NULL_COINS,
                       "capture_undo: null coins");
    if (!undo)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINS_MATH_ERR_NULL_UNDO,
                       "capture_undo: null undo");
    if (pos >= c->num_vout)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINS_MATH_ERR_OUT_OF_RANGE,
                       "capture_undo: pos=%u >= num_vout=%zu",
                       pos, c->num_vout);
    if (tx_out_is_null(&c->vout[pos]))
        return ZCL_ERR(DOMAIN_CONSENSUS_COINS_MATH_ERR_ALREADY_SPENT,
                       "capture_undo: vout[%u] already spent", pos);

    /* Snapshot the txout BEFORE we null it. */
    undo->txout = c->vout[pos];

    /* Spend in-place (already validated bounds + liveness above, so
     * coins_math_spend cannot fail). */
    (void)coins_math_spend(c, pos);

    /* If this spend made the parent coin fully-pruned, the undo
     * record must carry enough metadata to rebuild the coin on a
     * reorg. The legacy update_coins() did exactly this. */
    if (coins_math_is_pruned(c)) {
        undo->height   = (unsigned int)c->height;
        undo->coinbase = c->is_coinbase;
        undo->version  = c->version;
    }

    return ZCL_OK;
}

/* ── Pure amount compression ──────────────────────────────────────── */

uint64_t coins_math_compress_amount(uint64_t n)
{
    if (n == 0) return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (int)(n % 10);
        /* d ∈ [1, 9] by construction: e<9 means we stopped because
         * n%10 != 0; combined with n>0 invariant, d is non-zero. */
        n /= 10;
        return 1 + (n * 9 + (uint64_t)d - 1) * 10 + (uint64_t)e;
    }
    return 1 + (n - 1) * 10 + 9;
}

uint64_t coins_math_decompress_amount(uint64_t x)
{
    if (x == 0) return 0;
    x--;
    int e = (int)(x % 10);
    x /= 10;
    uint64_t n = 0;
    if (e < 9) {
        int d = (int)(x % 9) + 1;
        x /= 9;
        n = x * 10 + (uint64_t)d;
    } else {
        n = x + 1;
    }
    while (e) { n *= 10; e--; }
    return n;
}

/* ── Pure script-shape compression ────────────────────────────────── */

bool coins_math_script_compress(const struct script *s,
                                unsigned char *out, size_t *out_len)
{
    if (!s || !out || !out_len)
        return false;

    /* P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG */
    if (s->size == 25 && s->data[0] == OP_DUP && s->data[1] == OP_HASH160 &&
        s->data[2] == 20 && s->data[23] == OP_EQUALVERIFY &&
        s->data[24] == OP_CHECKSIG) {
        *out_len = 21;
        out[0] = 0x00;
        memcpy(out + 1, s->data + 3, 20);
        return true;
    }
    /* P2SH: OP_HASH160 <20> <hash> OP_EQUAL */
    if (s->size == 23 && s->data[0] == OP_HASH160 && s->data[1] == 20 &&
        s->data[22] == OP_EQUAL) {
        *out_len = 21;
        out[0] = 0x01;
        memcpy(out + 1, s->data + 2, 20);
        return true;
    }
    /* P2PK compressed: <33> <compressed pubkey> OP_CHECKSIG */
    if (s->size == 35 && s->data[0] == 33 && s->data[34] == OP_CHECKSIG &&
        (s->data[1] == 0x02 || s->data[1] == 0x03)) {
        *out_len = 33;
        out[0] = s->data[1];
        memcpy(out + 1, s->data + 2, 32);
        return true;
    }
    /* P2PK uncompressed: <65> <04 pubkey> OP_CHECKSIG */
    if (s->size == 67 && s->data[0] == 65 && s->data[66] == OP_CHECKSIG &&
        s->data[1] == 0x04) {
        struct pubkey pk;
        pubkey_set(&pk, s->data + 1, 65);
        if (!pubkey_is_fully_valid(&pk))
            return false;
        *out_len = 33;
        memcpy(out + 1, s->data + 2, 32);
        out[0] = 0x04 | (s->data[64] & 0x01);
        return true;
    }
    return false;
}

bool coins_math_script_decompress(struct script *s, unsigned int n_size,
                                  const unsigned char *in, size_t in_len)
{
    (void)in_len;
    if (!s || !in)
        return false;

    switch (n_size) {
    case 0x00: /* P2PKH */
        s->size = 25;
        s->data[0] = OP_DUP;
        s->data[1] = OP_HASH160;
        s->data[2] = 20;
        memcpy(s->data + 3, in, 20);
        s->data[23] = OP_EQUALVERIFY;
        s->data[24] = OP_CHECKSIG;
        return true;
    case 0x01: /* P2SH */
        s->size = 23;
        s->data[0] = OP_HASH160;
        s->data[1] = 20;
        memcpy(s->data + 2, in, 20);
        s->data[22] = OP_EQUAL;
        return true;
    case 0x02: /* compressed pubkey */
    case 0x03:
        s->size = 35;
        s->data[0] = 33;
        s->data[1] = (unsigned char)n_size;
        memcpy(s->data + 2, in, 32);
        s->data[34] = OP_CHECKSIG;
        return true;
    case 0x04: /* uncompressed pubkey */
    case 0x05: {
        unsigned char vch[33] = {0};
        vch[0] = (unsigned char)(n_size - 2);
        memcpy(vch + 1, in, 32);
        struct pubkey pk;
        pubkey_set(&pk, vch, 33);
        if (!pubkey_decompress(&pk))
            return false;
        /* Invariant after decompress: pk.size == 65. We don't assert
         * here (assert.h would pull a header into pure code); failing
         * the size check just falls out as a malformed-script error. */
        if (pk.size != 65)
            return false;
        s->size = 67;
        s->data[0] = 65;
        memcpy(s->data + 1, pk.vch, 65);
        s->data[66] = OP_CHECKSIG;
        return true;
    }
    }
    return false;
}

unsigned int coins_math_script_compress_special_size(unsigned int n_size)
{
    if (n_size == 0 || n_size == 1) return 20;
    if (n_size == 2 || n_size == 3 || n_size == 4 || n_size == 5) return 32;
    return 0;
}
