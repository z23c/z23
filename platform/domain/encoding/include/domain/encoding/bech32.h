/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * platform/domain/encoding/bech32.h — pure BIP-173 Bech32 codec.
 *
 * Bech32 is the SegWit / native-witness address format defined in
 * BIP-173 (and extended by BIP-350 / Bech32m). This module implements
 * the BIP-173 polymod (xor constant 1) variant only. Bech32m (xor
 * constant 0x2bc830a3, for witness v1+) is not provided here; if
 * needed it can be added as a sibling function with a different
 * constant — the rest of the algorithm is identical.
 *
 * Wire form:
 *   <hrp> "1" <data_chars> <6 checksum_chars>
 *
 *   - hrp:        1+ ASCII chars in [33..126], all same case
 *   - data/check: 5-bit symbols over the charset
 *                 "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
 *
 * This codec produces and consumes 5-bit values, NOT raw bytes —
 * callers convert between bits via convertbits helpers that live in
 * platform/modules/encoding/ (still TODO if you need them).
 *
 * Pure: no clock, no RNG, no I/O, no globals beyond `const` tables.
 * Internal VLAs are sized from input length AND hard-capped: decode
 * rejects strings over 1023 chars, encode rejects anything that would
 * produce a string over 1023 chars (symmetric — a string our own
 * decoder rejects is not worth building), so neither direction lets
 * an attacker-sized input exhaust the stack.
 *
 * Behavioral notes (preserved exactly from the legacy code):
 *
 *   - Maximum decode length is 1023 chars (BIP-173 says 90 — this
 *     implementation is intentionally more permissive to accommodate
 *     experimental payloads; kept exactly because changing it would
 *     break wallets that already round-trip longer strings).
 *
 *   - Mixed-case input is rejected (BIP-173). Pure uppercase decodes
 *     successfully and the HRP is lower-cased in `hrp_out`.
 *
 *   - The HRP separator is the LAST '1' in the string (rightmost
 *     scan); this lets the HRP itself contain '1' chars if needed.
 */

#ifndef ZCL_DOMAIN_ENCODING_BECH32_H
#define ZCL_DOMAIN_ENCODING_BECH32_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Encode a Bech32 (BIP-173) string. `values` are 5-bit symbols
 * (each value 0..31). Writes a NUL-terminated lowercase string to
 * `out`. Returns false if out_size is insufficient or any value
 * exceeds 31. */
bool domain_encoding_bech32_encode(char *out, size_t out_size,
                                   const char *hrp,
                                   const uint8_t *values, size_t values_len);

/* Decode a Bech32 (BIP-173) string.
 *
 *   str               NUL-terminated input
 *   hrp_out, hrp_size destination for lowercased HRP (NUL-terminated)
 *   data_out, ...     destination for the 5-bit payload (checksum
 *                     stripped); *data_len set on success
 *
 * Returns false on: length > 1023, non-printable / out-of-range
 * char, mixed case, missing separator, HRP too long for hrp_size,
 * data too long for data_size, invalid charset symbol, or polymod
 * checksum mismatch. */
bool domain_encoding_bech32_decode(char *hrp_out, size_t hrp_size,
                                   uint8_t *data_out, size_t data_size, size_t *data_len,
                                   const char *str);

#endif /* ZCL_DOMAIN_ENCODING_BECH32_H */
