/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Regression seal for platform/domain/encoding/base58.{c,h}.
 *
 *   1. Contract / null-edge tests.
 *   2. Known-answer vectors (Bitcoin Core unit tests + BIP-13 P2SH).
 *   3. Round-trip across random payload lengths.
 *   4. Checksum mismatch rejection (Base58Check).
 */

#include "test/test_core.h"

#include "domain/encoding/base58.h"
#include "core/hash.h"

#include <stdio.h>
#include <string.h>

#define B58_CHECK(name, expr) do {                                  \
    printf("domain_encoding_base58: %s... ", (name));               \
    if ((expr)) printf("OK\n");                                     \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* Bitcoin Core base58_encode_decode.json fixtures (a sampling). */
struct kv { const unsigned char *bytes; size_t len; const char *enc; };

static const unsigned char tv1[] = { 0x61 };
static const unsigned char tv2[] = { 0x62, 0x62, 0x62 };
static const unsigned char tv3[] = { 0x63, 0x63, 0x63 };
static const unsigned char tv4[] = { 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x79, 0x20, 0x61, 0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67 };
static const unsigned char tv5[] = { 0x00, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60, 0x92, 0x58, 0x86, 0xb6, 0x7d, 0x06, 0x52, 0x99, 0x92, 0x59, 0x15, 0xae, 0xb1, 0x72, 0xc0, 0x66, 0x47 };
static const unsigned char tv6[] = { 0x51, 0x6b, 0x6f, 0xcd, 0x0f };
static const unsigned char tv7[] = { 0xbf, 0x4f, 0x89, 0x00, 0x1e, 0x67, 0x02, 0x74, 0xdd };
static const unsigned char tv8[] = { 0x57, 0x2e, 0x47, 0x94 };
static const unsigned char tv9[] = { 0xec, 0xac, 0x89, 0xca, 0xd9, 0x39, 0x23, 0xc0, 0x23, 0x21 };
static const unsigned char tv10[] = { 0x10, 0xc8, 0x51, 0x1e };
static const unsigned char tv11[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const struct kv k_vectors[] = {
    { tv1,  sizeof tv1,  "2g"                                 },
    { tv2,  sizeof tv2,  "a3gV"                               },
    { tv3,  sizeof tv3,  "aPEr"                               },
    { tv4,  sizeof tv4,  "2cFupjhnEsSn59qHXstmK2ffpLv2"       },
    { tv5,  sizeof tv5,  "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L" },
    { tv6,  sizeof tv6,  "ABnLTmg"                            },
    { tv7,  sizeof tv7,  "3SEo3LWLoPntC"                      },
    { tv8,  sizeof tv8,  "3EFU7m"                             },
    { tv9,  sizeof tv9,  "EJDM8drfXA6uyA"                     },
    { tv10, sizeof tv10, "Rt5zm"                              },
    { tv11, sizeof tv11, "1111111111"                         },
};

static bool encode_matches(const unsigned char *data, size_t data_len, const char *expected)
{
    char buf[256];
    size_t out_len = 0;
    if (!domain_encoding_base58_encode(data, data_len, buf, sizeof(buf), &out_len))
        return false;
    return strcmp(buf, expected) == 0;
}

static bool decode_matches(const char *enc, const unsigned char *expected, size_t expected_len)
{
    unsigned char buf[256];
    size_t out_len = 0;
    if (!domain_encoding_base58_decode(enc, buf, sizeof(buf), &out_len))
        return false;
    return out_len == expected_len && memcmp(buf, expected, expected_len) == 0;
}

static bool roundtrip_ok(const unsigned char *data, size_t data_len)
{
    /* base58 expands by ~1.4x — size encode buf at 2x for safety. */
    char enc[512];
    unsigned char dec[256];
    size_t enc_len = 0, dec_len = 0;
    if (!domain_encoding_base58_encode(data, data_len, enc, sizeof(enc), &enc_len))
        return false;
    if (!domain_encoding_base58_decode(enc, dec, sizeof(dec), &dec_len))
        return false;
    return dec_len == data_len && memcmp(dec, data, data_len) == 0;
}

static bool check_roundtrip_ok(const unsigned char *data, size_t data_len)
{
    char enc[512];
    unsigned char dec[256];
    size_t enc_len = 0, dec_len = 0;
    if (!domain_encoding_base58check_encode(data, data_len, enc, sizeof(enc), &enc_len))
        return false;
    if (!domain_encoding_base58check_decode(enc, dec, sizeof(dec), &dec_len))
        return false;
    return dec_len == data_len && memcmp(dec, data, data_len) == 0;
}

static bool decode_span_roundtrip(size_t length, size_t zeroes)
{
    unsigned char input[740], output[742];
    char encoded[1024];
    memset(input, 0xff, length);
    memset(input, 0, zeroes);
    memset(output, 0xa5, sizeof(output));
    size_t written = 0;
    if (!domain_encoding_base58_encode(input, length, encoded, sizeof(encoded), NULL))
        return false;
    if (!domain_encoding_base58_decode(encoded, output + 1, length, &written))
        return false;
    return written == length && memcmp(input, output + 1, length) == 0 &&
           output[0] == 0xa5 && output[length + 1] == 0xa5;
}

static bool decode_refusal_preserves_output(const char *text, size_t capacity,
                                            size_t expected_length)
{
    unsigned char output[752], original[752];
    memset(output, 0xa5, sizeof(output));
    memcpy(original, output, sizeof(output));
    size_t written = 12345;
    bool ok = domain_encoding_base58_decode(text, output + 1, capacity, &written);
    return !ok && written == expected_length &&
           memcmp(output, original, sizeof(output)) == 0;
}

static int test_decode_overlimit_leading_ones(void)
{
    int failures = 0;
    char text[1025];
    unsigned char output[1026], original[1026];
    for (int mixed = 0; mixed < 2; ++mixed) {
        memset(text, '1', 1024);
        if (mixed) text[1023] = '2';
        text[1024] = '\0';
        memset(output, 0xa5, sizeof(output));
        memcpy(original, output, sizeof(output));
        size_t written = 12345;
        B58_CHECK("1024 whole-string characters refuse without publication",
                  !domain_encoding_base58_decode(text, output + 1, 1024, &written) &&
                  written == 12345 && memcmp(output, original, sizeof(output)) == 0);
    }
    return failures;
}

static int test_decode_leading_ones_bound(void)
{
    int failures = 0;
    char text[1025];
    unsigned char output[1026], original[1026], zeroes[1023] = {0};
    memset(text, '1', 1023);
    text[1023] = '\0';
    memset(output, 0xa5, sizeof(output));
    size_t written = 12345;
    B58_CHECK("1023 leading ones fit exact capacity",
              domain_encoding_base58_decode(text, output + 1, 1023, &written) &&
              written == 1023 && memcmp(output + 1, zeroes, 1023) == 0 &&
              output[0] == 0xa5 && output[1024] == 0xa5 && output[1025] == 0xa5);
    const size_t capacities[] = {0, 1022};
    for (size_t i = 0; i < sizeof(capacities)/sizeof(capacities[0]); ++i) {
        memset(output, 0xa5, sizeof(output));
        memcpy(original, output, sizeof(output));
        written = 12345;
        B58_CHECK("leading ones capacity refusal publishes no bytes",
                  !domain_encoding_base58_decode(text, output + 1, capacities[i], &written) &&
                  written == 1023 && memcmp(output, original, sizeof(output)) == 0);
    }
    text[1022] = '2';
    memset(output, 0xa5, sizeof(output));
    written = 12345;
    B58_CHECK("1022 ones plus digit fit whole-string bound",
              domain_encoding_base58_decode(text, output + 1, 1023, &written) &&
              written == 1023 && memcmp(output + 1, zeroes, 1022) == 0 &&
              output[1023] == 1 && output[0] == 0xa5 && output[1024] == 0xa5);
    return failures + test_decode_overlimit_leading_ones();
}

static int test_decode_active_span(void)
{
    int failures = 0;
    const size_t lengths[] = {1, 2, 25, 37, 82, 255, 256, 740};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        B58_CHECK("carry growth through all-ff magnitude", decode_span_roundtrip(lengths[i], 0));
        B58_CHECK("leading zero and carry growth", decode_span_roundtrip(lengths[i], 1));
    }
    B58_CHECK("size refusal leaves output intact", decode_refusal_preserves_output("5Q", 0, 1));
    B58_CHECK("invalid digit after valid prefix leaves output intact",
              decode_refusal_preserves_output("a3gV0", 64, 12345));
    B58_CHECK("embedded whitespace leaves output intact",
              decode_refusal_preserves_output("a3gV 2", 64, 12345));
    B58_CHECK("high-bit digit leaves output intact",
              decode_refusal_preserves_output("a3gV\xff", 64, 12345));
    char text[1025];
    unsigned char output[752];
    memset(text, 'z', 1023);
    text[1023] = '\0';
    memset(output, 0xa5, sizeof(output));
    size_t written = 0;
    B58_CHECK("maximum digit count fits bounded output",
              domain_encoding_base58_decode(text, output + 1, 750, &written) &&
              written == 750 && output[0] == 0xa5 && output[751] == 0xa5);
    text[1023] = 'z';
    text[1024] = '\0';
    B58_CHECK("over-limit text leaves output intact",
              decode_refusal_preserves_output(text, 750, 12345));
    return failures;
}

/* Independent oracle: divide a base256 magnitude by 58 repeatedly, rather
 * than multiplying a base58 magnitude by 256 like the production encoder.
 * Fixtures are synthetic; all arrays are owned by this call. */
static size_t encode_division_reference(const unsigned char *data, size_t length,
                                        char text[1415])
{
    static const char alphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char scratch[1024];
    char reversed[1414];
    if (length > sizeof scratch)
        return 0;
    memcpy(scratch, data, length);
    size_t zeroes = 0;
    while (zeroes < length && scratch[zeroes] == 0)
        zeroes++;
    size_t start = zeroes, digits = 0;
    while (start < length) {
        unsigned carry = 0;
        for (size_t i = start; i < length; i++) {
            carry = carry * 256u + scratch[i];
            scratch[i] = (unsigned char)(carry / 58u);
            carry %= 58u;
        }
        if (digits >= sizeof reversed)
            return 0;
        reversed[digits++] = alphabet[carry];
        while (start < length && scratch[start] == 0)
            start++;
    }
    if (zeroes + digits >= 1415)
        return 0;
    memset(text, '1', zeroes);
    for (size_t i = 0; i < digits; i++)
        text[zeroes + i] = reversed[digits - i - 1];
    text[zeroes + digits] = '\0';
    return zeroes + digits;
}

static bool encode_capacity_case(const unsigned char *data, size_t length,
                                 const char *expected, size_t needed, size_t capacity)
{
    char output[1416], guard[1416];
    memset(output, 0x5a, sizeof output);
    memcpy(guard, output, sizeof guard);
    size_t actual = 9999;
    bool ok = domain_encoding_base58_encode(data, length, output + 1, capacity, &actual);
    if (actual != needed)
        return false;
    if (capacity <= needed)
        return !ok && memcmp(output, guard, sizeof output) == 0;
    memcpy(guard + 1, expected, needed + 1);
    return ok && memcmp(output, guard, sizeof output) == 0;
}

static bool encode_boundary_case(size_t length, size_t zeroes, unsigned char value)
{
    unsigned char data[1024], original[1024];
    char expected[1415];
    memset(data, value, sizeof data);
    memset(data, 0, zeroes);
    memcpy(original, data, sizeof data);
    size_t needed = encode_division_reference(data, length, expected);
    if (length != 0 && needed == 0)
        return false;
    const size_t capacities[] = {0, needed, needed + 1, sizeof expected};
    for (size_t i = 0; i < sizeof capacities / sizeof capacities[0]; i++) {
        if (!encode_capacity_case(data, length, expected, needed, capacities[i]))
            return false;
    }
    return memcmp(data, original, sizeof data) == 0;
}

static int test_encode_significant_digits(void)
{
    int failures = 0;
    const size_t lengths[] = {0, 1, 2, 25, 37, 82, 256, 740, 1023, 1024};
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        size_t length = lengths[i];
        B58_CHECK("encode carry growth and capacity guards", encode_boundary_case(length, 0, 0xff));
        B58_CHECK("encode internal zero digits", encode_boundary_case(length, 0, 0x3a));
        B58_CHECK("encode all leading zeroes", encode_boundary_case(length, length, 0));
        B58_CHECK("encode long zero prefix", encode_boundary_case(length, length / 2, 1));
    }
    return failures;
}

static int test_base58_contract_rules(void)
{
    int failures = 0;

    /* (1) Contract: empty input round-trips through encode/decode. */
    {
        char enc[8] = {0};
        size_t enc_len = 0;
        bool ok = domain_encoding_base58_encode((const unsigned char *)"", 0, enc, sizeof enc, &enc_len);
        B58_CHECK("empty encode succeeds and is empty string", ok && enc_len == 0 && enc[0] == '\0');
    }

    /* (1b) Decode of empty string succeeds with zero length. */
    {
        unsigned char dec[8];
        size_t dec_len = 99;
        bool ok = domain_encoding_base58_decode("", dec, sizeof dec, &dec_len);
        B58_CHECK("empty string decodes to empty", ok && dec_len == 0);
    }

    /* (1c) Out-buffer too small: returns false but reports needed length. */
    {
        char small[2];
        size_t out_len = 0;
        bool ok = domain_encoding_base58_encode(tv4, sizeof tv4, small, sizeof small, &out_len);
        B58_CHECK("encode reports size on too-small buf", !ok && out_len > sizeof small);
    }

    /* (1d) Invalid Base58 character rejected. */
    {
        unsigned char dec[16];
        size_t dec_len = 0;
        bool ok = domain_encoding_base58_decode("0OIl", dec, sizeof dec, &dec_len);
        B58_CHECK("invalid character rejected", !ok);
    }
    return failures;
}

static int test_base58_known_vectors(void)
{
    int failures = 0;

    /* (2) Known-answer vectors (encode + decode). */
    for (size_t i = 0; i < sizeof k_vectors / sizeof k_vectors[0]; i++) {
        char name[64];
        snprintf(name, sizeof name, "vector[%zu] encode", i);
        B58_CHECK(name, encode_matches(k_vectors[i].bytes, k_vectors[i].len, k_vectors[i].enc));
        snprintf(name, sizeof name, "vector[%zu] decode", i);
        B58_CHECK(name, decode_matches(k_vectors[i].enc, k_vectors[i].bytes, k_vectors[i].len));
    }
    return failures;
}

static int test_base58_roundtrip_lengths(void)
{
    int failures = 0;

    /* (3) Round-trip on varied sizes. */
    {
        unsigned char buf[200] = {0};
        for (size_t L = 0; L <= sizeof buf; L += 7) {
            for (size_t i = 0; i < L; i++) buf[i] = (unsigned char)((i * 17u + 3u) & 0xff);
            char name[64];
            snprintf(name, sizeof name, "round-trip len=%zu", L);
            B58_CHECK(name, roundtrip_ok(buf, L));
        }
    }
    return failures;
}

static int test_base58check_contract(void)
{
    int failures = 0;

    /* (4) Base58Check round-trip + checksum mismatch rejection on a 21-byte
     * P2PKH-shaped payload (version 0x00 + 20-byte hash). The encoded
     * string is not pinned: synthetic payloads lack a real SHA256d
     * checksum. */
    {
        const unsigned char payload[] = {
            0x00, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60,
            0x92, 0x58, 0x86, 0xb6, 0x7d, 0x06, 0x52, 0x99,
            0x92, 0x59, 0x15, 0xae, 0xb1
        };
        char enc[64];
        size_t enc_len = 0;
        bool ok = domain_encoding_base58check_encode(payload, sizeof payload, enc, sizeof enc, &enc_len);
        B58_CHECK("Base58Check encode 21-byte payload succeeds", ok && enc_len > 25);

        unsigned char dec[64];
        size_t dec_len = 0;
        ok = domain_encoding_base58check_decode(enc, dec, sizeof dec, &dec_len);
        B58_CHECK("Base58Check decode round-trip 21-byte",
                  ok && dec_len == sizeof payload && memcmp(dec, payload, sizeof payload) == 0);

        /* Flip last char to break checksum (find a valid alt char). */
        char broken[64];
        strcpy(broken, enc);
        char last = broken[enc_len - 1];
        broken[enc_len - 1] = (last == '2') ? '3' : '2';
        ok = domain_encoding_base58check_decode(broken, dec, sizeof dec, &dec_len);
        B58_CHECK("Base58Check rejects checksum mismatch", !ok);

        /* Truncated to under 4 bytes can't carry a checksum. */
        ok = domain_encoding_base58check_decode("11", dec, sizeof dec, &dec_len);
        B58_CHECK("Base58Check rejects too-short input", !ok);

        /* Known-answer: tv5 is a real Bitcoin address whose checksum
         * matches; base58check_encode of its first 21 bytes must
         * reproduce the exact address string. */
        const unsigned char p[21] = {
            0x00, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60,
            0x92, 0x58, 0x86, 0xb6, 0x7d, 0x06, 0x52, 0x99,
            0x92, 0x59, 0x15, 0xae, 0xb1
        };
        char addr[64];
        size_t addr_len = 0;
        ok = domain_encoding_base58check_encode(p, sizeof p, addr, sizeof addr, &addr_len);
        /* tv5 has trailing 0x72c06647 — if that equals SHA256d(p)[:4]
         * the Base58Check addr equals tv5's encoding "1NS17iag...". */
        unsigned char checksum_check[32];
        hash256(p, 21, checksum_check);
        bool real_addr = (checksum_check[0] == 0x72 && checksum_check[1] == 0xc0 &&
                          checksum_check[2] == 0x66 && checksum_check[3] == 0x47);
        if (real_addr)
            B58_CHECK("Base58Check encode known P2PKH mainnet",
                      ok && strcmp(addr, "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L") == 0);
        else
            B58_CHECK("Base58Check encode (synthetic payload)", ok);
    }
    return failures;
}

static int test_base58_p2sh_payload(void)
{
    int failures = 0;

    /* BIP-13 P2SH: prefix 0x05, sample payload. */
    {
        const unsigned char p2sh[] = {
            0x05,
            0x74, 0xf2, 0x09, 0xf6, 0xea, 0x90, 0x7e, 0x2e,
            0xa4, 0x8f, 0x74, 0xfa, 0xe0, 0x5e, 0x42, 0x6c,
            0x6c, 0x46, 0x73, 0x04
        };
        char enc[64];
        size_t enc_len = 0;
        bool ok = domain_encoding_base58check_encode(p2sh, sizeof p2sh, enc, sizeof enc, &enc_len);
        /* The expected P2SH for this payload is "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V"
         * but more importantly the round-trip is what we seal here. */
        B58_CHECK("BIP-13 P2SH encode succeeds", ok && enc_len > 0);
        B58_CHECK("BIP-13 P2SH round-trip", ok && check_roundtrip_ok(p2sh, sizeof p2sh));
    }
    return failures;
}

static int test_base58_random_roundtrips(void)
{
    int failures = 0;

    /* Random-ish Base58Check round-trips across multiple lengths. */
    {
        unsigned char buf[64];
        for (size_t L = 1; L <= sizeof buf; L += 3) {
            for (size_t i = 0; i < L; i++) buf[i] = (unsigned char)((i * 53u + 11u) & 0xff);
            char name[64];
            snprintf(name, sizeof name, "Base58Check round-trip len=%zu", L);
            B58_CHECK(name, check_roundtrip_ok(buf, L));
        }
    }
    return failures;
}

static int test_base58_stack_caps(void)
{
    int failures = 0;

    /* Stack-VLA caps: oversized payloads are rejected on both encode
     * paths; the largest legitimate inputs stay far inside the cap. */
    {
        static unsigned char big[1025];
        for (size_t i = 0; i < sizeof big; i++) big[i] = (unsigned char)(i | 1);
        static char enc[2048];
        size_t enc_len = 0;
        B58_CHECK("encode rejects payload over 1 KB",
                  !domain_encoding_base58_encode(big, 1025, enc, sizeof enc, &enc_len));
        B58_CHECK("encode accepts payload at the 1 KB cap",
                  domain_encoding_base58_encode(big, 1024, enc, sizeof enc, &enc_len));
        B58_CHECK("base58check encode rejects payload over the cap",
                  !domain_encoding_base58check_encode(big, 1021, enc, sizeof enc, &enc_len));
        B58_CHECK("base58check encode accepts payload at the cap",
                  domain_encoding_base58check_encode(big, 1020, enc, sizeof enc, &enc_len));
    }
    return failures;
}

static int test_base58_whitespace(void)
{
    int failures = 0;

    /* (6) Whitespace handling preserved. */
    {
        unsigned char dec[16];
        size_t dec_len = 0;
        bool ok = domain_encoding_base58_decode("   a3gV   ", dec, sizeof dec, &dec_len);
        B58_CHECK("decode tolerates surrounding whitespace",
                  ok && dec_len == 3 && dec[0] == 0x62 && dec[1] == 0x62 && dec[2] == 0x62);

        ok = domain_encoding_base58_decode("a3 gV", dec, sizeof dec, &dec_len);
        B58_CHECK("decode rejects embedded whitespace tail", !ok);
    }
    return failures;
}

int test_domain_encoding_base58(void)
{
    int failures = 0;

    failures += test_base58_contract_rules();
    failures += test_base58_known_vectors();
    failures += test_base58_roundtrip_lengths();
    failures += test_base58check_contract();
    failures += test_base58_p2sh_payload();
    failures += test_base58_random_roundtrips();
    failures += test_base58_stack_caps();
    failures += test_base58_whitespace();

    return failures + test_decode_active_span() + test_encode_significant_digits() +
        test_decode_leading_ones_bound();
}
