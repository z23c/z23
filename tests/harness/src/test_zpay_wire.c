/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZPAY v1 wire-format, refusal and authentication cases for
 * contexts/wallet/modules/zid/src/zpay.c, written against the mutation
 * sweep's survivors. They run from test_zpay(), the group the sweep
 * measures that file with.
 *
 * The expected memo is rebuilt here from literal offsets, so a shifted
 * field, a wrong length or a changed constant in the encoder fails against
 * an independent statement of the format. Keys are fixture bytes.
 */

#include "zid/zpay.h"
#include "zid/zid.h"
#include "crypto/sha3.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ZW_CHECK(name, expr) do {                                     \
    printf("zpay_wire: %s... ", (name));                              \
    if ((expr)) printf("OK\n");                                       \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

#define ZW_PAD 0xF6
#define ZW_PREFIX(asset_len) (91u + (size_t)(asset_len) + 64u)
#define ZW_IDENTITY_LEN 151u

static void zw_fill(uint8_t *p, size_t n, uint8_t first)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(first + i);
}

/* Every field distinct, so a shifted offset or length shows. */
static void zw_env(struct zpay_envelope *e, const char *asset, uint8_t type,
                   bool reply)
{
    memset(e, 0, sizeof(*e));
    e->network = ZPAY_NETWORK_TESTNET;
    e->message_type = type;
    e->created_at = 0x1122334455667788ull;
    e->expires_at = 0x11223344556677AAull;
    zw_fill(e->nonce, 16, 0x10);
    zw_fill(e->request_id, 16, 0x30);
    zw_fill(e->invoice_digest, 32, 0x50);
    memcpy(e->asset, asset, strlen(asset) + 1);
    zw_fill(e->amount_commitment, 32, 0x90);
    e->has_reply = reply;
    zw_fill(e->reply_ref, 32, 0xB0);
}

static void zw_put_le(uint8_t *p, uint64_t v, int n)
{
    for (int i = 0; i < n; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* The spec, written out: the memo the encoder must produce. */
static void zw_expect(uint8_t m[ZPAY_MEMO_LEN], const struct zpay_envelope *e,
                      bool identity)
{
    size_t al = strlen(e->asset);
    size_t total = ZW_PREFIX(al) + (identity ? ZW_IDENTITY_LEN : 0u);
    memset(m, ZW_PAD, ZPAY_MEMO_LEN);
    memcpy(m, "ZPAY", 4);
    m[4] = 1;
    m[5] = e->network;
    m[6] = e->message_type;
    m[7] = (uint8_t)((identity ? 1 : 0) | (e->has_reply ? 2 : 0));
    zw_put_le(m + 8, total, 2);
    zw_put_le(m + 10, e->created_at, 8);
    zw_put_le(m + 18, e->expires_at, 8);
    memcpy(m + 26, e->nonce, 16);
    memcpy(m + 42, e->request_id, 16);
    memcpy(m + 58, e->invoice_digest, 32);
    m[90] = (uint8_t)al;
    memcpy(m + 91, e->asset, al);
    memcpy(m + 91 + al, e->amount_commitment, 32);
    if (e->has_reply)
        memcpy(m + 91 + al + 32, e->reply_ref, 32);
    else
        memset(m + 91 + al + 32, 0, 32);
}

static bool zw_all_equal(const uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != v)
            return false;
    return true;
}

static bool zw_contains(const uint8_t *hay, size_t hl, const uint8_t *needle,
                        size_t nl)
{
    for (size_t i = 0; i + nl <= hl; i++)
        if (memcmp(hay + i, needle, nl) == 0)
            return true;
    return false;
}

static void zw_digest(uint8_t out[32], const uint8_t *memo, size_t prefix_len)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)"ZPAY-envelope-v1", 16);
    sha3_256_write(&ctx, memo, prefix_len);
    sha3_256_finalize(&ctx, out);
}

static bool zw_same_fields(const struct zpay_envelope *a,
                           const struct zpay_envelope *b)
{
    return a->network == b->network && a->message_type == b->message_type &&
           a->created_at == b->created_at && a->expires_at == b->expires_at &&
           memcmp(a->nonce, b->nonce, 16) == 0 &&
           memcmp(a->request_id, b->request_id, 16) == 0 &&
           memcmp(a->invoice_digest, b->invoice_digest, 32) == 0 &&
           strcmp(a->asset, b->asset) == 0 &&
           memcmp(a->amount_commitment, b->amount_commitment, 32) == 0 &&
           a->has_reply == b->has_reply;
}

/* ── wire format: exact bytes, then the decode of those bytes ── */

static bool zw_wire_case(const char *asset, uint8_t type, bool reply)
{
    struct zpay_envelope in, out;
    uint8_t memo[ZPAY_MEMO_LEN], want[ZPAY_MEMO_LEN];
    zw_env(&in, asset, type, reply);
    zw_expect(want, &in, false);
    if (!zpay_memo_encode(memo, &in, NULL) ||
        memcmp(memo, want, sizeof(memo)) != 0)
        return false;
    if (!zpay_memo_decode(memo, &out) || !zw_same_fields(&in, &out))
        return false;
    if (reply && memcmp(out.reply_ref, in.reply_ref, 32) != 0)
        return false;
    return out.sender_authentication == ZPAY_SENDER_ANONYMOUS &&
           !out.has_identity_doc;
}

static int zw_wire_format(void)
{
    int failures = 0;
    char long_asset[ZPAY_ASSET_MAX + 1];
    memset(long_asset, 'A', ZPAY_ASSET_MAX);
    long_asset[ZPAY_ASSET_MAX] = '\0';

    ZW_CHECK("anonymous invoice with reply, 3-char asset, exact bytes",
             zw_wire_case("ZCL", ZPAY_MESSAGE_INVOICE, true));
    ZW_CHECK("anonymous payment without reply, exact bytes",
             zw_wire_case("ZCL", ZPAY_MESSAGE_PAYMENT, false));
    ZW_CHECK("anonymous receipt without reply, exact bytes",
             zw_wire_case("ZCL", ZPAY_MESSAGE_RECEIPT, false));
    ZW_CHECK("one-character asset, odd total length",
             zw_wire_case("Z", ZPAY_MESSAGE_RECEIPT, true));
    ZW_CHECK("four-character asset, odd total length",
             zw_wire_case("ZCLX", ZPAY_MESSAGE_INVOICE, false));
    ZW_CHECK("sixty-five-character asset (the maximum)",
             zw_wire_case(long_asset, ZPAY_MESSAGE_PAYMENT, true));
    return failures;
}

/* An unset reply reference is zero on the wire even if the caller left
 * junk in the struct. */
static int zw_reply_ref_zeroed(void)
{
    int failures = 0;
    struct zpay_envelope in;
    uint8_t memo[ZPAY_MEMO_LEN];
    zw_env(&in, "ZCL", ZPAY_MESSAGE_INVOICE, false);
    memset(in.reply_ref, 0xEE, 32);
    ZW_CHECK("encode", zpay_memo_encode(memo, &in, NULL));
    ZW_CHECK("no reply: the 32 reference bytes are zero, flag clear",
             zw_all_equal(memo + 94 + 32, 32, 0) && (memo[7] & 2) == 0);
    return failures;
}

/* ── asset spelling ───────────────────────────────────────────── */

static bool zw_asset_encodes(const char *bytes, size_t len)
{
    struct zpay_envelope e;
    uint8_t memo[ZPAY_MEMO_LEN];
    zw_env(&e, "ZCL", ZPAY_MESSAGE_INVOICE, false);
    memset(e.asset, 0, sizeof(e.asset));
    memcpy(e.asset, bytes, len);
    return zpay_memo_encode(memo, &e, NULL);
}

static int zw_asset_spellings(void)
{
    int failures = 0;
    char full[ZPAY_ASSET_MAX + 1];
    memset(full, 'A', sizeof(full));

    ZW_CHECK("asset 'A' (lowest letter) is accepted", zw_asset_encodes("A", 1));
    ZW_CHECK("asset 'Z' (highest letter) is accepted", zw_asset_encodes("Z", 1));
    ZW_CHECK("asset '0' (lowest digit) is accepted", zw_asset_encodes("0", 1));
    ZW_CHECK("asset '9' (highest digit) is accepted", zw_asset_encodes("9", 1));
    ZW_CHECK("asset with colon, hyphen, underscore is accepted",
             zw_asset_encodes("A:B-C_D", 7));
    ZW_CHECK("empty asset is refused", !zw_asset_encodes("", 0));
    ZW_CHECK("'@' just below 'A' is refused", !zw_asset_encodes("@", 1));
    ZW_CHECK("'[' just above 'Z' is refused", !zw_asset_encodes("[", 1));
    ZW_CHECK("'/' just below '0' is refused", !zw_asset_encodes("/", 1));
    ZW_CHECK("a bad FIRST character alone is refused",
             !zw_asset_encodes("aCL", 3));
    ZW_CHECK("a bad last character alone is refused",
             !zw_asset_encodes("ZCl", 3));
    ZW_CHECK("66 characters with no terminator is refused",
             !zw_asset_encodes(full, sizeof(full)));
    return failures;
}

/* ── encoder refusals leave the output untouched ──────────────── */

static bool zw_encode_refused(const struct zpay_envelope *e,
                              const uint8_t *seed)
{
    uint8_t memo[ZPAY_MEMO_LEN];
    memset(memo, 0xA5, sizeof(memo));
    return !zpay_memo_encode(memo, e, seed) &&
           zw_all_equal(memo, sizeof(memo), 0xA5);
}

static int zw_encoder_refusals(void)
{
    int failures = 0;
    struct zpay_envelope e;
    uint8_t seed[32];
    uint8_t memo[ZPAY_MEMO_LEN];
    zw_fill(seed, 32, 0x61);

    zw_env(&e, "ZCL", 0, false);
    ZW_CHECK("message type 0 is refused", zw_encode_refused(&e, NULL));
    zw_env(&e, "ZCL", 4, false);
    ZW_CHECK("message type 4 is refused", zw_encode_refused(&e, NULL));
    zw_env(&e, "ZCL", 1, false);
    e.network = 3;
    ZW_CHECK("network 3 is refused", zw_encode_refused(&e, NULL));
    zw_env(&e, "ZCL", 1, false);
    e.expires_at = e.created_at;
    ZW_CHECK("expiry equal to creation is refused", zw_encode_refused(&e, NULL));
    e.expires_at = e.created_at - 1;
    ZW_CHECK("expiry before creation is refused", zw_encode_refused(&e, NULL));
    zw_env(&e, "ZCL", 1, false);
    e.expires_at = e.created_at + 1;
    ZW_CHECK("expiry one after creation is accepted",
             zpay_memo_encode(memo, &e, NULL));
    zw_env(&e, "zcl", 1, false);
    ZW_CHECK("a refused signed encode leaves the output untouched",
             zw_encode_refused(&e, seed));
    ZW_CHECK("encode with a NULL envelope is refused",
             !zpay_memo_encode(memo, NULL, NULL));
    zw_env(&e, "ZCL", 1, false);
    ZW_CHECK("encode with a NULL output is refused",
             !zpay_memo_encode(NULL, &e, NULL));
    return failures;
}

/* ── decoder refusals ─────────────────────────────────────────── */

enum zw_flaw {
    FLAW_MAGIC_LAST, FLAW_VERSION, FLAW_NETWORK, FLAW_TYPE_LOW,
    FLAW_TYPE_HIGH, FLAW_FLAGS, FLAW_TOTAL_UP, FLAW_TOTAL_DOWN,
    FLAW_ASSET_ZERO, FLAW_ASSET_BYTE, FLAW_PAD_FIRST, FLAW_PAD_LAST,
    FLAW_END_HEADER = FLAW_PAD_LAST,
    FLAW_REPLY_FIRST, FLAW_REPLY_LAST, FLAW_EXPIRES_EQUAL,
    FLAW_EXPIRES_BEFORE, FLAW_COUNT
};

static void zw_corrupt_header(uint8_t *m, int flaw)
{
    switch (flaw) {
    case FLAW_MAGIC_LAST: m[3] = 'X'; break;
    case FLAW_VERSION: m[4] = 2; break;
    case FLAW_NETWORK: m[5] = 3; break;
    case FLAW_TYPE_LOW: m[6] = 0; break;
    case FLAW_TYPE_HIGH: m[6] = 4; break;
    default: m[7] |= 0x04; break;
    }
}

static void zw_corrupt_layout(uint8_t *m, int flaw)
{
    size_t total = (size_t)m[8] | ((size_t)m[9] << 8);
    switch (flaw) {
    case FLAW_TOTAL_UP: m[8]++; break;
    case FLAW_TOTAL_DOWN: m[8]--; break;
    case FLAW_ASSET_ZERO: m[90] = 0; break;
    case FLAW_ASSET_BYTE: m[91] = 'a'; break;
    case FLAW_PAD_FIRST: m[total] = 0; break;
    default: m[ZPAY_MEMO_LEN - 1] = 0; break;
    }
}

static void zw_corrupt(uint8_t *m, int flaw)
{
    if (flaw <= FLAW_FLAGS) {
        zw_corrupt_header(m, flaw);
        return;
    }
    if (flaw <= FLAW_PAD_LAST) {
        zw_corrupt_layout(m, flaw);
        return;
    }
    switch (flaw) {
    case FLAW_REPLY_FIRST: m[91 + 3 + 32] = 1; break;
    case FLAW_REPLY_LAST: m[91 + 3 + 63] = 1; break;
    case FLAW_EXPIRES_EQUAL: memcpy(m + 18, m + 10, 8); break;
    default: m[18] = m[10] - 1; memcpy(m + 19, m + 11, 7); break;
    }
}

static bool zw_flaw_refused(int flaw)
{
    struct zpay_envelope in, out;
    uint8_t memo[ZPAY_MEMO_LEN];
    zw_env(&in, "ZCL", ZPAY_MESSAGE_INVOICE, false);
    in.created_at = 1000;
    in.expires_at = 2000;
    if (!zpay_memo_encode(memo, &in, NULL))
        return false;
    zw_corrupt(memo, flaw);
    memset(&out, 0xA5, sizeof(out));
    if (zpay_memo_decode(memo, &out))
        return false;
    if (flaw > FLAW_END_HEADER)
        return true;
    /* Refused before any field is read: nothing of the memo is left in out. */
    return zw_all_equal((const uint8_t *)&out, sizeof(out), 0);
}

static int zw_decoder_refusals(void)
{
    int failures = 0;
    static const char *const names[FLAW_COUNT] = {
        "last magic byte", "version", "network", "type 0", "type 4",
        "reserved flag", "total length +1", "total length -1", "asset length 0",
        "asset byte", "first padding byte", "last padding byte",
        "reply reference with no reply flag, first byte",
        "reply reference with no reply flag, last byte",
        "expiry equal to creation", "expiry before creation",
    };
    for (int f = 0; f < FLAW_COUNT; f++)
        ZW_CHECK(names[f], zw_flaw_refused(f));
    return failures;
}

static int zw_decoder_nulls(void)
{
    int failures = 0;
    struct zpay_envelope e;
    uint8_t memo[ZPAY_MEMO_LEN];
    zw_env(&e, "ZCL", 1, false);
    ZW_CHECK("encode", zpay_memo_encode(memo, &e, NULL));
    ZW_CHECK("decode with a NULL memo is refused",
             !zpay_memo_decode(NULL, &e));
    ZW_CHECK("decode with a NULL output is refused",
             !zpay_memo_decode(memo, NULL));
    ZW_CHECK("authenticate of a NULL memo is INVALID, never anonymous",
             zpay_memo_authenticate(NULL, 1, &e) == ZPAY_SENDER_ZID_INVALID);
    return failures;
}

/* ── is_current ───────────────────────────────────────────────── */

static int zw_is_current(void)
{
    int failures = 0;
    struct zpay_envelope e;
    zw_env(&e, "ZCL", 1, false);
    e.created_at = 1000;
    e.expires_at = 2000;
    e.network = ZPAY_NETWORK_TESTNET;
    ZW_CHECK("current at the creation instant",
             zpay_envelope_is_current(&e, ZPAY_NETWORK_TESTNET, 1000));
    ZW_CHECK("not current one second before creation",
             !zpay_envelope_is_current(&e, ZPAY_NETWORK_TESTNET, 999));
    ZW_CHECK("current one second before expiry",
             zpay_envelope_is_current(&e, ZPAY_NETWORK_TESTNET, 1999));
    ZW_CHECK("not current at the expiry instant",
             !zpay_envelope_is_current(&e, ZPAY_NETWORK_TESTNET, 2000));
    ZW_CHECK("a NULL envelope is not current",
             !zpay_envelope_is_current(NULL, ZPAY_NETWORK_TESTNET, 1500));
    e.network = 3;
    ZW_CHECK("an out-of-range network never matches itself",
             !zpay_envelope_is_current(&e, 3, 1500));
    return failures;
}

/* ── identity binding ─────────────────────────────────────────── */

static bool zw_forge(uint8_t memo[ZPAY_MEMO_LEN],
                     const struct zpay_envelope *e, const uint8_t seed[32],
                     int flaw)
{
    size_t prefix = ZW_PREFIX(strlen(e->asset));
    uint8_t body[36];
    struct zid_doc doc;
    memcpy(body, "ZPAY", 4);
    zw_digest(body + 4, memo, prefix);
    if (flaw == 1)
        body[3] = 'X';
    if (flaw == 2)
        body[35] ^= 1;
    if (!zid_doc_sign(&doc, body, sizeof(body), e->created_at, e->expires_at,
                      seed))
        return false;
    return zid_doc_encode(memo + prefix, ZPAY_MEMO_LEN - prefix, &doc) ==
           ZW_IDENTITY_LEN;
}

static enum zpay_sender_authentication
zw_forged_result(const struct zpay_envelope *e, const uint8_t seed[32],
                 int flaw)
{
    uint8_t memo[ZPAY_MEMO_LEN];
    if (!zpay_memo_encode(memo, e, seed) || !zw_forge(memo, e, seed, flaw))
        return (enum zpay_sender_authentication)99;
    return zpay_memo_authenticate(memo, e->created_at, NULL);
}

static int zw_identity_binding(void)
{
    int failures = 0;
    struct zpay_envelope e;
    uint8_t seed[32];
    zw_fill(seed, 32, 0x61);
    zw_env(&e, "ZCL", ZPAY_MESSAGE_INVOICE, false);

    ZW_CHECK("a re-signed document with the right tag and digest verifies",
             zw_forged_result(&e, seed, 0) == ZPAY_SENDER_ZID_VERIFIED);
    ZW_CHECK("a signed document whose tag differs in its last byte is INVALID",
             zw_forged_result(&e, seed, 1) == ZPAY_SENDER_ZID_INVALID);
    ZW_CHECK("a signed document whose digest differs in its last byte is INVALID",
             zw_forged_result(&e, seed, 2) == ZPAY_SENDER_ZID_INVALID);
    return failures;
}

static int zw_signed_layout(void)
{
    int failures = 0;
    struct zpay_envelope e, out;
    uint8_t seed[32], memo[ZPAY_MEMO_LEN], want[ZPAY_MEMO_LEN], dg[32];
    zw_fill(seed, 32, 0x61);
    zw_env(&e, "ZCL", ZPAY_MESSAGE_PAYMENT, true);
    zw_expect(want, &e, true);
    ZW_CHECK("signed encode", zpay_memo_encode(memo, &e, seed));
    size_t prefix = ZW_PREFIX(3);
    ZW_CHECK("signed memo: prefix bytes are exactly the specified layout",
             memcmp(memo, want, prefix) == 0);
    ZW_CHECK("signed memo: padding starts after the identity document",
             zw_all_equal(memo + prefix + ZW_IDENTITY_LEN,
                          ZPAY_MEMO_LEN - prefix - ZW_IDENTITY_LEN, ZW_PAD));
    ZW_CHECK("signed memo decodes", zpay_memo_decode(memo, &out));
    zw_digest(dg, memo, prefix);
    ZW_CHECK("identity body is 36 bytes: ZPAY then SHA3-256 of the tagged prefix",
             out.has_identity_doc && out.identity_doc.body_len == 36 &&
             memcmp(out.identity_doc.body, "ZPAY", 4) == 0 &&
             memcmp(out.identity_doc.body + 4, dg, 32) == 0);
    ZW_CHECK("signed memo verifies at its creation instant",
             zpay_memo_authenticate(memo, e.created_at, &out) ==
             ZPAY_SENDER_ZID_VERIFIED);
    return failures;
}

/* A four-character asset makes the signed total length even, which a
 * flag read from the wrong byte would mistake for anonymous. */
static int zw_signed_even_total(void)
{
    int failures = 0;
    struct zpay_envelope e, out;
    uint8_t seed[32], memo[ZPAY_MEMO_LEN];
    zw_fill(seed, 32, 0x61);
    zw_env(&e, "ZCLX", ZPAY_MESSAGE_RECEIPT, false);
    ZW_CHECK("signed encode, 4-char asset", zpay_memo_encode(memo, &e, seed));
    ZW_CHECK("signed 4-char memo decodes with its identity",
             zpay_memo_decode(memo, &out) && out.has_identity_doc);
    ZW_CHECK("signed 4-char memo verifies",
             zpay_memo_authenticate(memo, e.created_at, NULL) ==
             ZPAY_SENDER_ZID_VERIFIED);
    return failures;
}

static int zw_authenticate_refusals(void)
{
    int failures = 0;
    struct zpay_envelope e, out;
    uint8_t seed[32], memo[ZPAY_MEMO_LEN];
    zw_fill(seed, 32, 0x61);
    zw_env(&e, "ZCL", ZPAY_MESSAGE_INVOICE, false);

    ZW_CHECK("encode anonymous", zpay_memo_encode(memo, &e, NULL));
    ZW_CHECK("anonymous memo authenticates as anonymous",
             zpay_memo_authenticate(memo, 1, NULL) == ZPAY_SENDER_ANONYMOUS);
    memo[3] = 'X';
    ZW_CHECK("a malformed memo is INVALID with an output",
             zpay_memo_authenticate(memo, 1, &out) == ZPAY_SENDER_ZID_INVALID);
    ZW_CHECK("a malformed memo is INVALID without an output",
             zpay_memo_authenticate(memo, 1, NULL) == ZPAY_SENDER_ZID_INVALID);

    ZW_CHECK("encode signed", zpay_memo_encode(memo, &e, seed));
    memo[ZW_PREFIX(3)] = 0xFF; /* identity document version byte */
    ZW_CHECK("an undecodable identity document refuses the whole memo",
             !zpay_memo_decode(memo, &out));
    ZW_CHECK("and authenticates as INVALID",
             zpay_memo_authenticate(memo, e.created_at, NULL) ==
             ZPAY_SENDER_ZID_INVALID);
    return failures;
}

/* ── no secret reaches any output ─────────────────────────────── */

static bool zw_leaks(const uint8_t *buf, size_t len, const uint8_t seed[32])
{
    return zw_contains(buf, len, seed, 32) ||
           zw_contains(buf, len, seed, 8) ||
           zw_contains(buf, len, seed + 24, 8);
}

static int zw_no_secret_in_output(void)
{
    int failures = 0;
    struct zpay_envelope e, out;
    uint8_t seed[32], memo[ZPAY_MEMO_LEN];
    zw_fill(seed, 32, 0xD0);
    zw_env(&e, "ZCL", ZPAY_MESSAGE_INVOICE, true);

    ZW_CHECK("signed encode", zpay_memo_encode(memo, &e, seed));
    ZW_CHECK("the signing seed is nowhere in the memo",
             !zw_leaks(memo, sizeof(memo), seed));
    ZW_CHECK("decode", zpay_memo_decode(memo, &out));
    ZW_CHECK("the signing seed is nowhere in the decoded envelope",
             !zw_leaks((const uint8_t *)&out, sizeof(out), seed));
    ZW_CHECK("authenticate with output",
             zpay_memo_authenticate(memo, e.created_at, &out) ==
             ZPAY_SENDER_ZID_VERIFIED);
    ZW_CHECK("the signing seed is nowhere in the authenticated envelope",
             !zw_leaks((const uint8_t *)&out, sizeof(out), seed));
    return failures;
}

int zpay_wire_tests(void)
{
    int failures = 0;
    failures += zw_wire_format();
    failures += zw_reply_ref_zeroed();
    failures += zw_asset_spellings();
    failures += zw_encoder_refusals();
    failures += zw_decoder_refusals();
    failures += zw_decoder_nulls();
    failures += zw_is_current();
    failures += zw_identity_binding();
    failures += zw_signed_layout();
    failures += zw_signed_even_total();
    failures += zw_authenticate_refusals();
    failures += zw_no_secret_in_output();
    return failures;
}
