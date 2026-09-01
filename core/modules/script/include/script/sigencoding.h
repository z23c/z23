/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2017-2018 The Bitcoin developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SCRIPT_SIGENCODING_H
#define ZCL_SCRIPT_SIGENCODING_H

#include "script/script_error.h"
#include "script/sighashtype.h"
#include "script/script_flags.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

static inline struct sighash_type sig_get_hash_type(const unsigned char *sig,
                                                    size_t siglen)
{
    if (siglen == 0)
        return (struct sighash_type){0};
    return (struct sighash_type){sig[siglen - 1]};
}

/* Signature- and pubkey-encoding gates run BEFORE every checksig. CONSENSUS
 * surface (see core/modules/script/src/sigencoding.c) — these decide whether a
 * malformed encoding fails the script. All three return true = "encoding
 * acceptable, proceed"; on false they set `*serror` (SCRIPT_ERR_SIG_* /
 * SCRIPT_ERR_PUBKEYTYPE) and the caller aborts the script. The checks they
 * apply are gated on SCRIPT_VERIFY_* bits in `flags`, so a CLEARED bit
 * DISABLES that check.
 *
 * check_data_signature_encoding — for OP_CHECKDATASIG (no trailing hashtype
 * byte). An empty signature (siglen == 0) is always accepted (the opcode
 * then fails the verify itself). Otherwise the FULL `sig` must be valid
 * strict-DER (always enforced) and, iff SCRIPT_VERIFY_LOW_S is set, must
 * have low-S (BIP62 rule 5); clearing SCRIPT_VERIFY_LOW_S accepts high-S
 * signatures. */
bool check_data_signature_encoding(const unsigned char *sig, size_t siglen,
                                   uint32_t flags, ScriptError *serror);

/* check_transaction_signature_encoding — for OP_CHECKSIG / OP_CHECKMULTISIG,
 * where `sig` carries a trailing 1-byte sighash type. Empty sig (siglen == 0)
 * is always accepted. Otherwise: the DER body (sig[0..siglen-2], i.e.
 * excluding the hashtype byte) must be valid strict-DER (always enforced);
 * iff SCRIPT_VERIFY_LOW_S set, must be low-S; and iff SCRIPT_VERIFY_STRICTENC
 * set, the trailing hashtype byte must be a defined SIGHASH combination
 * (ALL/NONE/SINGLE, optionally |ANYONECANPAY) else SCRIPT_ERR_SIG_HASHTYPE.
 * Clearing SCRIPT_VERIFY_STRICTENC disables only the hashtype-validity check;
 * the DER structural check is NOT flag-gated and always applies. */
bool check_transaction_signature_encoding(const unsigned char *sig,
                                          size_t siglen, uint32_t flags,
                                          ScriptError *serror);

/* check_pubkey_encoding — validates a public key shape before checksig. The
 * entire check is gated on SCRIPT_VERIFY_STRICTENC: when that flag is CLEAR
 * this function always returns true (any byte string is accepted as a
 * pubkey). When set, the key must be either 33 bytes with a 0x02/0x03 prefix
 * (compressed) or 65 bytes with a 0x04 prefix (uncompressed); anything else
 * fails SCRIPT_ERR_PUBKEYTYPE. Note this validates ENCODING only, not that
 * the point is on-curve — that is the checker->check_sig callback's job. */
bool check_pubkey_encoding(const unsigned char *pubkey, size_t len,
                           uint32_t flags, ScriptError *serror);

#endif
