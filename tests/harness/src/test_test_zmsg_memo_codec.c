/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic pure-function coverage for the on-chain ZMSG memo codec
 * (core/modules/net/src/zmsg.c: zmsg_memo_encode / zmsg_memo_decode).
 *
 * The codec packs an arbitrary UTF-8 payload plus an optional 32-byte
 * reply-to msg_id into the fixed 512-byte Sapling memo field (see the
 * wire-format comment in core/modules/net/include/net/zmsg.h). Both functions are
 * pure (no I/O, no clock, no global state) — encode/decode is a straight
 * byte-layout round trip, so this is exercised entirely with in-memory
 * buffers, no node.db and no live node. */

#include "test/test_core.h"

#include "net/zmsg.h"

#include <string.h>

/* Fill a payload buffer with a recognizable, position-dependent pattern so
 * a copy that drops, shifts, or truncates bytes shows up as a mismatch
 * rather than accidentally matching on all-same-byte data. */
static void zmc_fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed + i);
}

int test_test_zmsg_memo_codec(void);
int test_test_zmsg_memo_codec(void)
{
    int failures = 0;

    /* ── zmsg_memo_encode: rejection paths ────────────────────────── */

    TEST("memo_encode: NULL out is rejected") {
        uint8_t payload[4] = {1, 2, 3, 4};
        ASSERT(!zmsg_memo_encode(NULL, payload, sizeof(payload), NULL));
        PASS();
    }

    TEST("memo_encode: payload_len over the 474-byte max is rejected") {
        uint8_t out[ZMSG_MEMO_LEN];
        uint8_t big[ZMSG_MEMO_MAX_PAYLOAD + 1];
        zmc_fill_pattern(big, sizeof(big), 0);
        ASSERT(!zmsg_memo_encode(out, big, sizeof(big), NULL));
        PASS();
    }

    TEST("memo_encode: NULL payload with non-zero payload_len is rejected") {
        uint8_t out[ZMSG_MEMO_LEN];
        ASSERT(!zmsg_memo_encode(out, NULL, 10, NULL));
        PASS();
    }

    TEST("memo_encode: rejected calls leave `out` unmodified") {
        uint8_t out[ZMSG_MEMO_LEN];
        memset(out, 0xAB, sizeof(out));
        uint8_t big[ZMSG_MEMO_MAX_PAYLOAD + 1];
        zmc_fill_pattern(big, sizeof(big), 0);
        ASSERT(!zmsg_memo_encode(out, big, sizeof(big), NULL));
        bool untouched = true;
        for (size_t i = 0; i < sizeof(out); i++)
            if (out[i] != 0xAB) { untouched = false; break; }
        ASSERT(untouched);
        PASS();
    }

    /* ── zmsg_memo_encode: happy path + byte-layout checks ────────── */

    TEST("memo_encode: zero-length payload, no reply_to — header + padding") {
        uint8_t out[ZMSG_MEMO_LEN];
        ASSERT(zmsg_memo_encode(out, NULL, 0, NULL));
        ASSERT_EQ(out[0], ZMSG_MEMO_MAGIC_0);
        ASSERT_EQ(out[1], ZMSG_MEMO_MAGIC_1);
        ASSERT_EQ(out[2], ZMSG_MEMO_VERSION);
        ASSERT_EQ(out[3], 0); /* no HAS_REPLY_TO flag */
        ASSERT_EQ(out[4], 0); /* payload_len low byte */
        ASSERT_EQ(out[5], 0); /* payload_len high byte */
        /* reply_to field (offset 6..37) is all-zero when unused */
        bool reply_zero = true;
        for (int i = 6; i < ZMSG_MEMO_HEADER_LEN; i++)
            if (out[i] != 0) { reply_zero = false; break; }
        ASSERT(reply_zero);
        /* everything from the header end to the end of the memo is the
         * 0xF6 pad byte (no payload bytes at all). */
        bool fully_padded = true;
        for (int i = ZMSG_MEMO_HEADER_LEN; i < ZMSG_MEMO_LEN; i++)
            if (out[i] != ZMSG_MEMO_PAD_BYTE) { fully_padded = false; break; }
        ASSERT(fully_padded);
        PASS();
    }

    TEST("memo_encode: small payload — payload_len little-endian + padding") {
        uint8_t out[ZMSG_MEMO_LEN];
        uint8_t payload[5] = { 'h', 'e', 'l', 'l', 'o' };
        ASSERT(zmsg_memo_encode(out, payload, sizeof(payload), NULL));
        ASSERT_EQ(out[4], sizeof(payload)); /* low byte */
        ASSERT_EQ(out[5], 0);               /* high byte */
        ASSERT(memcmp(out + ZMSG_MEMO_HEADER_LEN, payload,
                       sizeof(payload)) == 0);
        /* padding starts right after the payload */
        bool padded_after = true;
        for (int i = ZMSG_MEMO_HEADER_LEN + (int)sizeof(payload);
             i < ZMSG_MEMO_LEN; i++)
            if (out[i] != ZMSG_MEMO_PAD_BYTE) { padded_after = false; break; }
        ASSERT(padded_after);
        PASS();
    }

    TEST("memo_encode: reply_to sets the HAS_REPLY_TO flag and is copied") {
        uint8_t out[ZMSG_MEMO_LEN];
        uint8_t reply_to[32];
        zmc_fill_pattern(reply_to, sizeof(reply_to), 0x40);
        uint8_t payload[2] = { 'h', 'i' };
        ASSERT(zmsg_memo_encode(out, payload, sizeof(payload), reply_to));
        ASSERT_EQ(out[3], ZMSG_MEMO_FLAG_HAS_REPLY_TO);
        ASSERT(memcmp(out + 6, reply_to, 32) == 0);
        PASS();
    }

    TEST("memo_encode: max-length payload (474 bytes) exactly fills the memo") {
        uint8_t out[ZMSG_MEMO_LEN];
        uint8_t payload[ZMSG_MEMO_MAX_PAYLOAD];
        zmc_fill_pattern(payload, sizeof(payload), 7);
        ASSERT(zmsg_memo_encode(out, payload, sizeof(payload), NULL));
        ASSERT_EQ(out[4], (uint8_t)(ZMSG_MEMO_MAX_PAYLOAD & 0xFF));
        ASSERT_EQ(out[5], (uint8_t)((ZMSG_MEMO_MAX_PAYLOAD >> 8) & 0xFF));
        ASSERT(memcmp(out + ZMSG_MEMO_HEADER_LEN, payload,
                       sizeof(payload)) == 0);
        /* header(38) + max payload(474) == 512: no room left for padding */
        ASSERT_EQ(ZMSG_MEMO_HEADER_LEN + (int)sizeof(payload), ZMSG_MEMO_LEN);
        PASS();
    }

    /* ── zmsg_memo_decode: rejection paths ────────────────────────── */

    TEST("memo_decode: NULL memo is rejected") {
        struct zmsg_memo out;
        ASSERT(!zmsg_memo_decode(NULL, &out));
        PASS();
    }

    TEST("memo_decode: NULL out is rejected") {
        uint8_t memo[ZMSG_MEMO_LEN];
        ASSERT(zmsg_memo_encode(memo, NULL, 0, NULL));
        ASSERT(!zmsg_memo_decode(memo, NULL));
        PASS();
    }

    TEST("memo_decode: wrong magic bytes are rejected quietly") {
        uint8_t memo[ZMSG_MEMO_LEN];
        ASSERT(zmsg_memo_encode(memo, NULL, 0, NULL));
        memo[0] = 0x00; /* corrupt magic0 — this is what every non-ZMSG
                          * shielded memo looks like to this decoder */
        struct zmsg_memo out;
        ASSERT(!zmsg_memo_decode(memo, &out));
        PASS();
    }

    TEST("memo_decode: unknown version is rejected") {
        uint8_t memo[ZMSG_MEMO_LEN];
        ASSERT(zmsg_memo_encode(memo, NULL, 0, NULL));
        memo[2] = (uint8_t)(ZMSG_MEMO_VERSION + 1);
        struct zmsg_memo out;
        ASSERT(!zmsg_memo_decode(memo, &out));
        PASS();
    }

    TEST("memo_decode: a reserved flag bit is rejected") {
        uint8_t memo[ZMSG_MEMO_LEN];
        ASSERT(zmsg_memo_encode(memo, NULL, 0, NULL));
        memo[3] = (uint8_t)(memo[3] | 0x02); /* bit1 is reserved (0) */
        struct zmsg_memo out;
        ASSERT(!zmsg_memo_decode(memo, &out));
        PASS();
    }

    TEST("memo_decode: payload_len past the 474-byte ceiling is rejected") {
        uint8_t memo[ZMSG_MEMO_LEN];
        ASSERT(zmsg_memo_encode(memo, NULL, 0, NULL));
        uint16_t bad_len = (uint16_t)(ZMSG_MEMO_MAX_PAYLOAD + 1);
        memo[4] = (uint8_t)(bad_len & 0xFF);
        memo[5] = (uint8_t)((bad_len >> 8) & 0xFF);
        struct zmsg_memo out;
        ASSERT(!zmsg_memo_decode(memo, &out));
        PASS();
    }

    TEST("memo_decode: a failed decode still zeroes `out` first") {
        uint8_t memo[ZMSG_MEMO_LEN];
        memset(memo, 0, sizeof(memo)); /* wrong magic (all zero) */
        struct zmsg_memo out;
        memset(&out, 0xCD, sizeof(out));
        ASSERT(!zmsg_memo_decode(memo, &out));
        ASSERT_EQ(out.version, 0);
        ASSERT_EQ(out.flags, 0);
        ASSERT(!out.has_reply_to);
        ASSERT_EQ(out.payload_len, 0);
        PASS();
    }

    /* ── round trip: encode -> decode preserves every field ───────── */

    TEST("round trip: no payload, no reply_to") {
        uint8_t memo[ZMSG_MEMO_LEN];
        ASSERT(zmsg_memo_encode(memo, NULL, 0, NULL));
        struct zmsg_memo out;
        ASSERT(zmsg_memo_decode(memo, &out));
        ASSERT_EQ(out.version, ZMSG_MEMO_VERSION);
        ASSERT_EQ(out.flags, 0);
        ASSERT(!out.has_reply_to);
        ASSERT_EQ(out.payload_len, 0);
        bool reply_zero = true;
        for (int i = 0; i < 32; i++)
            if (out.reply_to[i] != 0) { reply_zero = false; break; }
        ASSERT(reply_zero);
        PASS();
    }

    TEST("round trip: payload + reply_to preserved byte-for-byte") {
        uint8_t memo[ZMSG_MEMO_LEN];
        uint8_t payload[64];
        uint8_t reply_to[32];
        zmc_fill_pattern(payload, sizeof(payload), 1);
        zmc_fill_pattern(reply_to, sizeof(reply_to), 0x80);
        ASSERT(zmsg_memo_encode(memo, payload, sizeof(payload), reply_to));

        struct zmsg_memo out;
        ASSERT(zmsg_memo_decode(memo, &out));
        ASSERT_EQ(out.version, ZMSG_MEMO_VERSION);
        ASSERT(out.has_reply_to);
        ASSERT_EQ(out.flags, ZMSG_MEMO_FLAG_HAS_REPLY_TO);
        ASSERT(memcmp(out.reply_to, reply_to, 32) == 0);
        ASSERT_EQ(out.payload_len, (uint16_t)sizeof(payload));
        ASSERT(memcmp(out.payload, payload, sizeof(payload)) == 0);
        PASS();
    }

    TEST("round trip: max-length payload (474 bytes)") {
        uint8_t memo[ZMSG_MEMO_LEN];
        uint8_t payload[ZMSG_MEMO_MAX_PAYLOAD];
        zmc_fill_pattern(payload, sizeof(payload), 3);
        ASSERT(zmsg_memo_encode(memo, payload, sizeof(payload), NULL));

        struct zmsg_memo out;
        ASSERT(zmsg_memo_decode(memo, &out));
        ASSERT_EQ(out.payload_len, (uint16_t)ZMSG_MEMO_MAX_PAYLOAD);
        ASSERT(memcmp(out.payload, payload, sizeof(payload)) == 0);
        ASSERT(!out.has_reply_to);
        PASS();
    }

    TEST("round trip: single-byte payload at the small-length boundary") {
        uint8_t memo[ZMSG_MEMO_LEN];
        uint8_t payload[1] = { 0x42 };
        ASSERT(zmsg_memo_encode(memo, payload, sizeof(payload), NULL));
        struct zmsg_memo out;
        ASSERT(zmsg_memo_decode(memo, &out));
        ASSERT_EQ(out.payload_len, 1);
        ASSERT_EQ(out.payload[0], 0x42);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_test_zmsg_memo_codec: all passed\n");
    else
        printf("test_test_zmsg_memo_codec: %d FAILED\n", failures);
    return failures;
}
