/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * platform/domain/encoding/base58.h — pure Base58 and Base58Check codecs.
 *
 * Base58 alphabet (Bitcoin):
 *   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
 *
 * Base58Check appends a 4-byte SHA256d (double-SHA-256) checksum
 * before encoding; decoders reject on checksum mismatch. This is the
 * canonical encoding for legacy P2PKH/P2SH addresses, WIF private
 * keys, and BIP32 extended keys (xpub/xprv).
 *
 * Pure: no clock, no RNG, no I/O, no globals beyond `const` lookup
 * tables. Internal VLAs are sized from input length AND hard-capped:
 * decode rejects strings over 1023 chars, encode rejects payloads
 * over 1 KB, so neither direction lets an attacker-sized input
 * exhaust the stack. Every Bitcoin/Zclassic address and key family
 * is tens of bytes — far inside the cap. The codec is deterministic
 * and replayable.
 *
 * Behavioral notes (preserved from the legacy platform/modules/encoding code):
 *
 *   - base58_decode() tolerates ASCII whitespace at the start, end,
 *     and as a tail terminator (`while (isspace) p++; if (*p) return
 *     false;`). Embedded whitespace is rejected.
 *
 *   - base58_decode("") returns true with *out_len == 0.
 *
 *   - base58check_decode() uses an internal 256-byte temporary; any
 *     base58 string whose decoded length exceeds 256 bytes is
 *     rejected via the inner base58_decode() check. This matches the
 *     pre-existing constraint and bounds every Bitcoin/Zclassic
 *     address family by a wide margin.
 *
 *   - The internal `carry == 0` invariant comes from the algebraic
 *     invariants of base-58 long division and cannot trip on any
 *     byte-string input. It is checked as a guarded `return false`
 *     (wiping the intermediate first) rather than an assert(): every
 *     address, WIF, xpub/xprv and explorer URL segment the node
 *     accepts reaches this codec, and assert() is live in the node's
 *     release build, so an assert here would turn one malformed
 *     input into a process abort. Both codecs are TOTAL: any input
 *     either encodes/decodes or returns false.
 *
 * Layering: platform/domain/encoding/ may #include from util/, core/, crypto/
 * — the only external dep is `core/hash.h::hash256` for the
 * Base58Check checksum. No persistence, no ports, no platform.
 *
 * The platform/modules/encoding/base58.h public API remains the canonical caller
 * surface; platform/modules/encoding/src/base58.c is now a thin byte-identical
 * wrapper around these symbols.
 */

#ifndef ZCL_DOMAIN_ENCODING_BASE58_H
#define ZCL_DOMAIN_ENCODING_BASE58_H

#include <stdbool.h>
#include <stddef.h>

/* Encode raw bytes to Base58. Writes a NUL-terminated string into `out`.
 *
 *   data, data_len   input bytes (may be empty)
 *   out, out_size    destination buffer (must hold result + NUL)
 *   *out_len         set to the encoded length (excluding NUL)
 *
 * Returns true on success; false if out_size is insufficient
 * (*out_len is still set so callers can size buffers on retry). */
bool domain_encoding_base58_encode(const unsigned char *data, size_t data_len,
                                   char *out, size_t out_size, size_t *out_len);

/* Decode a Base58 string into raw bytes.
 *
 *   psz              NUL-terminated input; leading/trailing ASCII
 *                    whitespace tolerated, embedded whitespace
 *                    rejected.
 *   out, out_size    destination buffer
 *   *out_len         set to the decoded length on success
 *
 * Returns true on success; false on invalid character, embedded
 * whitespace, or out_size too small. */
bool domain_encoding_base58_decode(const char *psz,
                                   unsigned char *out, size_t out_size, size_t *out_len);

/* Base58Check encode: appends a 4-byte SHA256d checksum then
 * Base58-encodes. Buffers and return semantics match base58_encode. */
bool domain_encoding_base58check_encode(const unsigned char *data, size_t data_len,
                                        char *out, size_t out_size, size_t *out_len);

/* Base58Check decode: Base58-decodes, verifies the trailing 4-byte
 * SHA256d checksum, and returns the payload (checksum stripped).
 *
 * Returns false on any of: invalid Base58, decoded length < 4,
 * checksum mismatch, decoded length > 256 (internal scratch cap),
 * or out_size too small for the stripped payload. */
bool domain_encoding_base58check_decode(const char *str,
                                        unsigned char *out, size_t out_size, size_t *out_len);

#endif /* ZCL_DOMAIN_ENCODING_BASE58_H */
