/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton
 *
 * Pure Base58 / Base58Check address codec.
 * See platform/domain/encoding/include/domain/encoding/base58.h for the contract;
 * this file is intentionally allocation-free and dependency-light (only
 * core/hash.h for the SHA256d checksum).
 */

#include "domain/encoding/base58.h"
#include "core/hash.h"
#include "support/cleanse.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

static const char base58_chars[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Fixed bounds for the scratch buffers below.
 *
 * Each entry point already rejects over-long input, so the scratch sizes were
 * always bounded — but spelling them as `unsigned char b58[b58_size]` made
 * them variable-length arrays, i.e. a stack allocation whose size is a runtime
 * value. That is the construct `-Wvla` exists to forbid: if any future edit
 * moves or weakens the length check above, a VLA turns it straight into stack
 * exhaustion, while a fixed array turns it into a bounds check that fails
 * loudly. The static_asserts below bind each buffer to the cap that justifies
 * it, so the two cannot drift apart silently. */
#define B58_ENCODE_MAX_INPUT 1024u
#define B58_ENCODE_BUF       (B58_ENCODE_MAX_INPUT * 138u / 100u + 1u)  /* 1414 */
#define B58_DECODE_MAX_INPUT 1023u
#define B58_DECODE_BUF       (B58_DECODE_MAX_INPUT * 733u / 1000u + 1u) /* 750 */
#define B58_CHECK_MAX_INPUT  1020u
#define B58_CHECK_BUF        (B58_CHECK_MAX_INPUT + 4u)                 /* 1024 */

static_assert(B58_ENCODE_BUF >= B58_ENCODE_MAX_INPUT * 138u / 100u + 1u,
              "base58 encode scratch must cover the encode input cap");
static_assert(B58_DECODE_BUF >= B58_DECODE_MAX_INPUT * 733u / 1000u + 1u,
              "base58 decode scratch must cover the decode input cap");
static_assert(B58_CHECK_BUF >= B58_CHECK_MAX_INPUT + 4u,
              "base58check scratch must cover payload + 4-byte checksum");

/* Borrow a bounded initialized suffix; the caller owns and erases the full
 * scratch. Its size depends only on bytes consumed, not on their values. */
static bool base58_encode_byte(unsigned char *digits, size_t size,
                               unsigned char byte)
{
    int carry = byte;
    for (size_t i = size; i > 0; i--) {
        carry += 256 * digits[i - 1];
        digits[i - 1] = carry % 58;
        carry /= 58;
    }
    return carry == 0;
}

bool domain_encoding_base58_encode(const unsigned char *data, size_t data_len,
                                   char *out, size_t out_size, size_t *out_len)
{
    /* Bound the stack VLA below: every legitimate encode input (addresses,
     * WIF keys, BIP32 extended keys) is tens of bytes; mirror the decode
     * side's 1023-char cap rather than let a caller-sized payload exhaust
     * the stack. */
    if (data_len > B58_ENCODE_MAX_INPUT)
        return false;

    const unsigned char *pbegin = data;
    const unsigned char *pend = data + data_len;

    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }

    size_t b58_size = (size_t)(pend - pbegin) * 138 / 100 + 1;
    if (b58_size > B58_ENCODE_BUF)
        return false; /* unreachable given the cap above; fail, never overflow */
    unsigned char b58[B58_ENCODE_BUF];
    memset(b58, 0, b58_size);

    size_t processed = 0;
    while (pbegin != pend) {
        /* Reuse the full-input bound for the prefix processed so far. This
         * grows monotonically to b58_size; the unvisited prefix is zero. */
        size_t active = ++processed * 138 / 100 + 1;
        /* Total function on purpose: every address, WIF, xpub/xprv and
         * explorer URL segment the node accepts reaches this codec, and
         * assert() is live in release builds (-DNDEBUG is not set for the
         * node), so an assert here would let one malformed input abort the
         * whole process. b58_size is derived from the input length, so a
         * non-zero carry can only mean that derivation is wrong — fail the
         * call instead of the node. */
        if (!base58_encode_byte(b58 + b58_size - active, active, *pbegin)) {
            memory_cleanse(b58, b58_size);
            return false;
        }
        pbegin++;
    }

    size_t skip = 0;
    while (skip < b58_size && b58[skip] == 0)
        skip++;

    size_t result_len = zeroes + (b58_size - skip);
    if (out_len)
        *out_len = result_len;
    if (result_len + 1 > out_size) {
        /* b58 may hold secret-derived digits (base58check_encode of a
         * private key); wipe the intermediate before the error return. */
        memory_cleanse(b58, b58_size);
        return false;
    }

    for (int i = 0; i < zeroes; i++)
        out[i] = '1';
    for (size_t i = skip; i < b58_size; i++)
        out[zeroes + (i - skip)] = base58_chars[b58[i]];
    out[result_len] = '\0';
    /* b58's last read is the loop above; wipe the secret-derived digits. */
    memory_cleanse(b58, b58_size);
    return true;
}

/* Borrowed, zero-initialized scratch. Multiplication by 58 grows the
 * significant suffix by at most one byte; carry <= 57 throughout. The
 * caller retains ownership and cleanses the entire initialized span. */
static bool base58_decode_digit(unsigned char *bytes, size_t size,
                                size_t *used, int carry)
{
    size_t span = *used < size ? *used + 1 : *used;
    size_t start = size - span;
    for (size_t i = size; i > start; i--) {
        carry += 58 * bytes[i - 1];
        bytes[i - 1] = carry % 256;
        carry /= 256;
    }
    if (carry != 0)
        return false;
    if (bytes[start] != 0)
        *used = span;
    return true;
}

static bool base58_decode_digits(const char **text, unsigned char *bytes,
                                 size_t size, size_t *used)
{
    const char *p = *text;
    while (*p && !isspace((unsigned char)*p)) {
        const char *ch = strchr(base58_chars, *p);
        if (ch == NULL)
            return false;
        if (!base58_decode_digit(bytes, size, used, (int)(ch - base58_chars)))
            return false;
        p++;
    }
    *text = p;
    return true;
}

bool domain_encoding_base58_decode(const char *psz,
                                   unsigned char *out, size_t out_size, size_t *out_len)
{
    /* Bound the whole string before counting its leading zero digits. This
     * also stops scanning oversized inputs before any counter can overflow. */
    size_t input_len = 0;
    while (input_len <= B58_DECODE_MAX_INPUT && psz[input_len])
        ++input_len;
    if (input_len > B58_DECODE_MAX_INPUT)
        return false;

    while (*psz && isspace((unsigned char)*psz))
        psz++;

    size_t zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }

    input_len = strlen(psz);
    /* Bound the stack VLA below: no valid base58 address or key string
     * approaches this length, so a longer input is malformed — reject it
     * rather than let an attacker-sized string exhaust the stack (mirrors the
     * length cap in bech32_decode). */
    if (input_len > B58_DECODE_MAX_INPUT)
        return false;
    size_t b256_size = input_len * 733 / 1000 + 1;
    if (b256_size > B58_DECODE_BUF)
        return false; /* unreachable given the cap above; fail, never overflow */
    unsigned char b256[B58_DECODE_BUF];
    memset(b256, 0, b256_size);

    const char *p = psz;
    size_t used = 0;
    if (!base58_decode_digits(&p, b256, b256_size, &used)) {
        /* Reject invalid digits or overflow without publishing a partial
         * result; scratch may contain secret-derived bytes. */
        memory_cleanse(b256, b256_size);
        return false;
    }

    while (isspace((unsigned char)*p))
        p++;
    if (*p != 0) {
        memory_cleanse(b256, b256_size);
        return false;
    }

    size_t skip = b256_size - used;

    size_t result_len = zeroes + (b256_size - skip);
    if (out_len)
        *out_len = result_len;
    if (result_len > out_size) {
        memory_cleanse(b256, b256_size);
        return false;
    }

    memset(out, 0, zeroes);
    memcpy(out + zeroes, b256 + skip, b256_size - skip);
    /* b256's last read is the memcpy above; wipe the decoded payload. */
    memory_cleanse(b256, b256_size);
    return true;
}

bool domain_encoding_base58check_encode(const unsigned char *data, size_t data_len,
                                        char *out, size_t out_size, size_t *out_len)
{
    /* Same 1 KB stack-VLA bound as base58_encode (which would reject
     * data_len + 4 anyway); check here so the buf VLA is born bounded. */
    if (data_len > B58_CHECK_MAX_INPUT)
        return false;

    unsigned char buf[B58_CHECK_BUF];
    memcpy(buf, data, data_len);
    unsigned char hash[32];
    hash256(data, data_len, hash);
    memcpy(buf + data_len, hash, 4);
    bool ok = domain_encoding_base58_encode(buf, data_len + 4, out, out_size, out_len);
    /* buf holds the secret payload (e.g. a WIF private key); its last
     * read is the encode call above. Wipe on both success and error. */
    memory_cleanse(buf, data_len + 4);
    return ok;
}

bool domain_encoding_base58check_decode(const char *str,
                                        unsigned char *out, size_t out_size, size_t *out_len)
{
    unsigned char tmp[256];
    size_t tmp_len = 0;
    if (!domain_encoding_base58_decode(str, tmp, sizeof(tmp), &tmp_len)) {
        /* tmp may hold a decoded secret payload (xprv/privkey). */
        memory_cleanse(tmp, sizeof(tmp));
        return false;
    }
    if (tmp_len < 4) {
        memory_cleanse(tmp, sizeof(tmp));
        return false;
    }

    unsigned char hash[32];
    hash256(tmp, tmp_len - 4, hash);
    if (memcmp(hash, tmp + tmp_len - 4, 4) != 0) {
        memory_cleanse(tmp, sizeof(tmp));
        return false;
    }

    size_t result_len = tmp_len - 4;
    if (out_len)
        *out_len = result_len;
    if (result_len > out_size) {
        memory_cleanse(tmp, sizeof(tmp));
        return false;
    }

    memcpy(out, tmp, result_len);
    /* tmp's last read is the memcpy above; wipe the decoded payload. */
    memory_cleanse(tmp, sizeof(tmp));
    return true;
}
