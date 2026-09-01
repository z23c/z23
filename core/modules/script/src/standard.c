/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Thin wrappers over the pure detectors in
 * domain/consensus/script_standard.{c,h}. Signatures preserved verbatim
 * so the wallet/explorer/controller call-sites are unchanged. The
 * recognition logic itself is in the domain layer (pure, no clock /
 * RNG / IO). */

#include "script/standard.h"

#include "domain/consensus/script_standard.h"
#include "core/hash.h"

#include <string.h>

/* Compile-time sanity: the lib txnouttype tags MUST agree numerically
 * with their domain counterparts, since every wrapper below relies on
 * the bit-identical mapping (we just cast). */
_Static_assert((int)TX_NONSTANDARD == (int)DOMAIN_SCRIPT_TX_NONSTANDARD,
               "txnouttype/domain enum drift: NONSTANDARD");
_Static_assert((int)TX_PUBKEY      == (int)DOMAIN_SCRIPT_TX_PUBKEY,
               "txnouttype/domain enum drift: PUBKEY");
_Static_assert((int)TX_PUBKEYHASH  == (int)DOMAIN_SCRIPT_TX_PUBKEYHASH,
               "txnouttype/domain enum drift: PUBKEYHASH");
_Static_assert((int)TX_SCRIPTHASH  == (int)DOMAIN_SCRIPT_TX_SCRIPTHASH,
               "txnouttype/domain enum drift: SCRIPTHASH");
_Static_assert((int)TX_MULTISIG    == (int)DOMAIN_SCRIPT_TX_MULTISIG,
               "txnouttype/domain enum drift: MULTISIG");
_Static_assert((int)TX_NULL_DATA   == (int)DOMAIN_SCRIPT_TX_NULL_DATA,
               "txnouttype/domain enum drift: NULL_DATA");

const char *get_txn_output_type(enum txnouttype t)
{
    return domain_consensus_script_txn_output_type_name(
            (enum domain_script_txnouttype)t);
}

void script_id_from_script(struct script_id *out, const struct script *s)
{
    /* Wrapper preserves the legacy void return; the domain call only
     * fails on NULL inputs, which the caller contract rules out. */
    (void)domain_consensus_script_id_from_script(s, out->hash.data);
}

bool script_solver(const struct script *s, enum txnouttype *type_out,
                   unsigned char solutions[][65], size_t solution_sizes[],
                   size_t *num_solutions)
{
    enum domain_script_txnouttype dt = DOMAIN_SCRIPT_TX_NONSTANDARD;
    bool matched = false;
    /* Legacy callers pass row-20 buffers (see standard.h docstring);
     * the domain function tolerates smaller. We pass 20 unconditionally
     * because the legacy ABI hard-codes a 20-row stack buffer at every
     * caller. */
    struct zcl_result r = domain_consensus_script_solver(
            s, solutions, solution_sizes, 20,
            &dt, num_solutions, &matched);
    if (!r.ok) {
        if (type_out) *type_out = TX_NONSTANDARD;
        if (num_solutions) *num_solutions = 0;
        return false;
    }
    *type_out = (enum txnouttype)dt;
    return matched;
}

int script_sig_args_expected(enum txnouttype t,
                             const unsigned char solutions[][65],
                             const size_t solution_sizes[],
                             size_t num_solutions)
{
    return domain_consensus_script_sig_args_expected(
            (enum domain_script_txnouttype)t,
            solutions, solution_sizes, num_solutions);
}

bool script_extract_destination(const struct script *s,
                                struct tx_destination *dest_out)
{
    bool matched = false;
    struct zcl_result r = domain_consensus_script_extract_destination(
            s, dest_out, &matched);
    if (!r.ok) return false;
    return matched;
}

enum script_type utxo_classify_script(const uint8_t *script, size_t len,
                                      uint8_t addr_hash[20], bool *has_addr)
{
    *has_addr = false;

    /* P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG */
    if (len == 25 &&
        script[0] == OP_DUP && script[1] == OP_HASH160 &&
        script[2] == 20 &&
        script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        memcpy(addr_hash, script + 3, 20);
        *has_addr = true;
        return SCRIPT_P2PKH;
    }

    /* P2SH: OP_HASH160 <20> <hash> OP_EQUAL */
    if (len == 23 &&
        script[0] == OP_HASH160 && script[1] == 20 &&
        script[22] == OP_EQUAL) {
        memcpy(addr_hash, script + 2, 20);
        *has_addr = true;
        return SCRIPT_P2SH;
    }

    if (len > 0 && script[0] == OP_RETURN)
        return SCRIPT_OP_RETURN;

    return SCRIPT_OTHER;
}

bool tx_destination_is_valid(const struct tx_destination *dest)
{
    return dest->type != DEST_NONE;
}

void script_for_p2pkh(struct script *out, const struct key_id *key)
{
    out->size = 25;
    out->data[0] = OP_DUP;
    out->data[1] = OP_HASH160;
    out->data[2] = 20;
    memcpy(out->data + 3, key->id.data, 20);
    out->data[23] = OP_EQUALVERIFY;
    out->data[24] = OP_CHECKSIG;
}

void script_for_p2sh(struct script *out, const struct script_id *script_hash)
{
    out->size = 23;
    out->data[0] = OP_HASH160;
    out->data[1] = 20;
    memcpy(out->data + 2, script_hash->hash.data, 20);
    out->data[22] = OP_EQUAL;
}

void script_for_multisig(struct script *out, int n_required,
                         const struct pubkey *keys, size_t num_keys)
{
    out->size = 0;
    out->data[out->size++] = (unsigned char)(OP_1 + n_required - 1);

    for (size_t i = 0; i < num_keys; i++) {
        unsigned char klen = (unsigned char)keys[i].size;
        out->data[out->size++] = klen;
        memcpy(out->data + out->size, keys[i].vch, klen);
        out->size += klen;
    }

    out->data[out->size++] = (unsigned char)(OP_1 + (int)num_keys - 1);
    out->data[out->size++] = OP_CHECKMULTISIG;
}

void script_for_destination(struct script *out, const struct tx_destination *dest)
{
    switch (dest->type) {
    case DEST_KEY_ID:
        script_for_p2pkh(out, &dest->id.key);
        break;
    case DEST_SCRIPT_ID:
        script_for_p2sh(out, &dest->id.script);
        break;
    case DEST_NONE:
        out->size = 0;
        break;
    }
}
