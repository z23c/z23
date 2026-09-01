/* Copyright (c) 2014-2016 The Bitcoin Core developers
 * Copyright (c) 2016-2018 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_KEY_IO_H
#define ZCL_KEY_IO_H

#include "domain/encoding/base58.h"
#include "script/standard.h"
#include "keys/key.h"
#include <stdbool.h>

/* Base58Check-encode a payment destination into out (NUL-terminated, bounded
 * by outsize). Uses pubkey_prefix for a DEST_KEY_ID (P2PKH) or script_prefix
 * for a DEST_SCRIPT_ID (P2SH) — the network version bytes that select the
 * address type. Returns false for an unsupported destination type or if the
 * encoded string does not fit in outsize. */
bool encode_destination(const struct tx_destination *dest,
                        const unsigned char *pubkey_prefix, size_t pfx_len,
                        const unsigned char *script_prefix, size_t spfx_len,
                        char *out, size_t outsize);

/* Decode a Base58Check address string into dest, matching its leading version
 * bytes against pubkey_prefix (-> DEST_KEY_ID) or script_prefix
 * (-> DEST_SCRIPT_ID). On failure dest->type is set to DEST_NONE and false is
 * returned (bad checksum, wrong length, or unrecognized prefix). */
bool decode_destination(const char *str,
                        const unsigned char *pubkey_prefix, size_t pfx_len,
                        const unsigned char *script_prefix, size_t spfx_len,
                        struct tx_destination *dest);

/* Base58Check-encode a private key as a WIF string into out, prefixed with the
 * given secret-key version bytes and appending the compression flag byte when
 * the key is compressed. The working buffer is wiped before return. Returns
 * false if the result does not fit in outsize. */
bool encode_secret(const struct privkey *key,
                   const unsigned char *prefix, size_t pfx_len,
                   char *out, size_t outsize);

/* Decode a WIF string into key, requiring the leading prefix to match and a
 * 32-byte payload (with an optional trailing 0x01 marking a compressed key).
 * The working buffer is wiped before return. Returns false on a bad checksum
 * or a wrong prefix/length; the 32-byte payload is accepted as-is and marked
 * valid (no secp256k1 scalar-range check is performed here). */
bool decode_secret(const char *str,
                   const unsigned char *prefix, size_t pfx_len,
                   struct privkey *key);

#endif
