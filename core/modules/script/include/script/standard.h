/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SCRIPT_STANDARD_H
#define ZCL_SCRIPT_STANDARD_H

#include "keys/pubkey.h"
#include "script/script.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

enum txnouttype {
    TX_NONSTANDARD,
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA
};

enum script_type {
    SCRIPT_P2PKH = 0,
    SCRIPT_P2SH  = 1,
    SCRIPT_OP_RETURN = 2,
    SCRIPT_MULTISIG = 3,
    SCRIPT_OTHER = 255
};

#define MAX_OP_RETURN_RELAY 223

struct script_id {
    struct uint160 hash;
};

enum tx_dest_type {
    DEST_NONE,
    DEST_KEY_ID,
    DEST_SCRIPT_ID
};

struct tx_destination {
    enum tx_dest_type type;
    union {
        struct key_id key;
        struct script_id script;
    } id;
};

const char *get_txn_output_type(enum txnouttype t);

/* Recognize a standard scriptPubKey template and extract its data pushes.
 * Wraps the pure domain_consensus_script_solver. Mirrors zclassicd
 * Solver(). Used for standardness, wallet ownership, and address display —
 * NOT a consensus gate (it does not run scripts).
 *
 * On a match: sets *type_out to the TX_* class and fills `solutions` /
 * `solution_sizes` with that class's pushes, *num_solutions = count, returns
 * true. The caller MUST provide a 20-ROW `solutions` buffer (each row 65
 * bytes) — the wrapper hard-codes that capacity; smaller buffers are a
 * caller bug. Per-type extracted pushes (verified against script_standard.c):
 *   TX_SCRIPTHASH  -> [20-byte script hash]
 *   TX_PUBKEYHASH  -> [20-byte key hash]
 *   TX_PUBKEY      -> [33- or 65-byte pubkey]
 *   TX_MULTISIG    -> [1-byte m][n pubkeys][1-byte n]  (so num_solutions=n+2)
 *   TX_NULL_DATA   -> matched, but NO solutions emitted (num_solutions=0)
 * On no match: *type_out = TX_NONSTANDARD, *num_solutions = 0, returns false.
 * A NULL/invalid input also yields TX_NONSTANDARD + false. */
bool script_solver(const struct script *s, enum txnouttype *type_out,
                   unsigned char solutions[][65], size_t solution_sizes[],
                   size_t *num_solutions);

/* Number of scriptSig items a standard input of type `t` is expected to
 * supply (the `solutions` from script_solver, for TX_MULTISIG). Returns:
 *   TX_PUBKEY      -> 1   (one signature)
 *   TX_PUBKEYHASH  -> 2   (signature + pubkey)
 *   TX_SCRIPTHASH  -> 1   (counts the serialized redeem script push; the
 *                          redeem script's own args are counted separately)
 *   TX_MULTISIG    -> m + 1  (m signatures + the leading OP_0 dummy), where
 *                          m is solutions[0][0]; needs num_solutions>=1
 *   TX_NONSTANDARD / TX_NULL_DATA -> -1  ("not applicable / unknown")
 * Returns -1 on malformed multisig solutions. */
int script_sig_args_expected(enum txnouttype t,
                             const unsigned char solutions[][65],
                             const size_t solution_sizes[],
                             size_t num_solutions);

/* Extract the single spendable destination (key-id or script-id) from a
 * standard scriptPubKey. Wraps domain_consensus_script_extract_destination.
 * Returns true and sets *dest_out only for P2PKH (DEST_KEY_ID), P2SH
 * (DEST_SCRIPT_ID), and bare P2PK (DEST_KEY_ID, derived from the pubkey —
 * rejected if the pubkey is invalid). TX_MULTISIG and TX_NULL_DATA have no
 * single destination: returns false with dest_out->type = DEST_NONE. A
 * non-standard or NULL script also returns false. */
bool script_extract_destination(const struct script *s,
                                struct tx_destination *dest_out);

/* Classify a scriptPubKey for UTXO indexing and extract address hash.
 * Single shared implementation; keep storage/model callers on this path. */
enum script_type utxo_classify_script(const uint8_t *script, size_t len,
                                      uint8_t addr_hash[20], bool *has_addr);

void script_for_p2pkh(struct script *out, const struct key_id *key);
void script_for_p2sh(struct script *out, const struct script_id *script_hash);
void script_for_multisig(struct script *out, int n_required,
                         const struct pubkey *keys, size_t num_keys);

void script_id_from_script(struct script_id *out, const struct script *s);

bool tx_destination_is_valid(const struct tx_destination *dest);
void script_for_destination(struct script *out, const struct tx_destination *dest);

#endif
