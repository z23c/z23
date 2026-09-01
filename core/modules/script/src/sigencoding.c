/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2017-2018 The Bitcoin developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "script/sigencoding.h"
#include "keys/pubkey.h"

static bool is_valid_signature_encoding(const unsigned char *sig, size_t len)
{
    if (len < 8 || len > 72)
        return false;

    if (sig[0] != 0x30)
        return false;

    if (sig[1] != len - 2)
        return false;

    if (sig[2] != 0x02)
        return false;

    uint32_t lenR = sig[3];
    if (lenR == 0)
        return false;

    if (sig[4] & 0x80)
        return false;

    if (lenR > (len - 7))
        return false;

    if (lenR > 1 && sig[4] == 0x00 && !(sig[5] & 0x80))
        return false;

    uint32_t startS = lenR + 4;
    if (sig[startS] != 0x02)
        return false;

    uint32_t lenS = sig[startS + 1];
    if (lenS == 0)
        return false;

    if (sig[startS + 2] & 0x80)
        return false;

    if ((size_t)(startS + lenS + 2) != len)
        return false;

    if (lenS > 1 && sig[startS + 2] == 0x00 && !(sig[startS + 3] & 0x80))
        return false;

    return true;
}

static bool check_raw_signature_encoding(const unsigned char *sig, size_t len,
                                         uint32_t flags, ScriptError *serror)
{
    if (!is_valid_signature_encoding(sig, len))
        return set_script_error(serror, SCRIPT_ERR_SIG_DER);

    if ((flags & SCRIPT_VERIFY_LOW_S) && !pubkey_check_low_s(sig, len))
        return set_script_error(serror, SCRIPT_ERR_SIG_HIGH_S);

    return true;
}

bool check_data_signature_encoding(const unsigned char *sig, size_t siglen,
                                   uint32_t flags, ScriptError *serror)
{
    if (siglen == 0)
        return true;

    return check_raw_signature_encoding(sig, siglen, flags, serror);
}

bool check_transaction_signature_encoding(const unsigned char *sig,
                                          size_t siglen, uint32_t flags,
                                          ScriptError *serror)
{
    if (siglen == 0)
        return true;

    if (!check_raw_signature_encoding(sig, siglen - 1, flags, serror))
        return false;

    if ((flags & SCRIPT_VERIFY_STRICTENC) &&
        !sighash_is_defined(sig_get_hash_type(sig, siglen)))
        return set_script_error(serror, SCRIPT_ERR_SIG_HASHTYPE);

    return true;
}

bool check_pubkey_encoding(const unsigned char *pubkey, size_t len,
                           uint32_t flags, ScriptError *serror)
{
    if (flags & SCRIPT_VERIFY_STRICTENC) {
        if (len == 33) {
            if (pubkey[0] != 0x02 && pubkey[0] != 0x03)
                return set_script_error(serror, SCRIPT_ERR_PUBKEYTYPE);
        } else if (len == 65) {
            if (pubkey[0] != 0x04)
                return set_script_error(serror, SCRIPT_ERR_PUBKEYTYPE);
        } else {
            return set_script_error(serror, SCRIPT_ERR_PUBKEYTYPE);
        }
    }
    return true;
}
