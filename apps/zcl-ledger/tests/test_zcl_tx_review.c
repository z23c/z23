/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_review.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t from_hex(const char *hex, uint8_t *wire, size_t capacity) {
    size_t length = strlen(hex);
    assert(length % 2 == 0 && length / 2 <= capacity);
    for (size_t i = 0; i < length / 2; ++i) {
        int high = nibble(hex[2 * i]), low = nibble(hex[2 * i + 1]);
        assert(high >= 0 && low >= 0);
        wire[i] = (uint8_t)((high << 4) | low);
    }
    return length / 2;
}

static void test_chain_coinbase(void) {
    /* Height 3139216 ZCL v4 coinbase from the node's wire-evidence corpus. */
    static const char hex[] =
        "0400008085202f8901000000000000000000000000000000000000000000000000"
        "0000000000000000ffffffff220390e62f04995e256a088e27ab4e000000002f"
        "7a706f6f6c2e63612f8e27ab4e2f00ffffffff01e40b5402000000001976a9144a"
        "440303eb700db2ed916471a063404e72f498d888ac000000000000000000000000"
        "00000000000000";
    uint8_t wire[256];
    size_t length = from_hex(hex, wire, sizeof wire);
    zcl_tx_review review = {0};
    assert(zcl_tx_review_parse(wire, length, &review) == 0);
    assert(review.transparent_inputs == 1);
    assert(review.transparent_outputs == 1);
    assert(review.transparent_output_zat == 39062500);
    assert(review.sapling_spends == 0 && review.sapling_outputs == 0);
    for (size_t i = 0; i < length; ++i)
        assert(zcl_tx_review_parse(wire, i, &review) < 0);
    wire[length] = 0;
    assert(zcl_tx_review_parse(wire, length + 1, &review) < 0);
}

static void test_sapling_layout(void) {
    uint8_t wire[8 + 2 + 8 + 8 + 1 + 384 + 1 + 948 + 1 + 64] = {0};
    const uint8_t header[] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    memcpy(wire, header, sizeof header);
    size_t length = sizeof header + 2 + 8 + 8;
    wire[length++] = 1;
    length += 384;
    wire[length++] = 1;
    length += 948;
    wire[length++] = 0;
    length += 64;
    assert(length == sizeof wire);
    zcl_tx_review review = {0};
    assert(zcl_tx_review_parse(wire, length, &review) == 0);
    assert(review.sapling_spends == 1 && review.sapling_outputs == 1);
    assert(zcl_tx_review_parse(wire, length - 1, &review) < 0);
    wire[26] = 0xfd;
    assert(zcl_tx_review_parse(wire, length, &review) < 0);
}

static void test_rejections(void) {
    uint8_t wire[30] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    zcl_tx_review review = {0};
    assert(zcl_tx_review_parse(wire, 29, &review) == 0);
    wire[0] = 3;
    assert(zcl_tx_review_parse(wire, 29, &review) < 0);
    wire[0] = 4;
    wire[4] = 0;
    assert(zcl_tx_review_parse(wire, 29, &review) < 0);
    wire[4] = 0x85;
    wire[8] = 0xfd;
    assert(zcl_tx_review_parse(wire, 29, &review) < 0);
    wire[8] = 0;
    wire[18] = 1;
    assert(zcl_tx_review_parse(wire, 29, &review) == 0);
    assert(review.value_balance_zat == 1);
    memset(wire + 18, 0xff, 8);
    assert(zcl_tx_review_parse(wire, 29, &review) == 0);
    assert(review.value_balance_zat == -1);
    wire[28] = 1;
    assert(zcl_tx_review_parse(wire, 29, &review) < 0);
    assert(zcl_tx_review_parse(NULL, 29, &review) < 0);
    assert(zcl_tx_review_parse(wire, 29, NULL) < 0);
    assert(zcl_tx_review_parse(wire, ZCL_TX_REVIEW_MAX_BYTES + 1,
                               &review) < 0);
}

static void test_public_value_and_sprout_layout(void) {
    uint8_t wire[8 + 1 + 1 + 8 + 1 + 4 + 4 + 8 + 1 + 1 + 1 + 1634 + 96] = {0};
    const uint8_t header[] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    memcpy(wire, header, sizeof header);
    size_t offset = sizeof header;
    wire[offset++] = 0;
    wire[offset++] = 1;
    wire[offset++] = 1;
    offset += 7;
    wire[offset++] = 0;
    offset += 4 + 4 + 8;
    wire[offset++] = 0;
    wire[offset++] = 0;
    wire[offset++] = 1;
    offset += 1634 + 96;
    assert(offset == sizeof wire);
    zcl_tx_review review = {0};
    assert(zcl_tx_review_parse(wire, sizeof wire, &review) == 0);
    assert(review.transparent_outputs == 1);
    assert(review.transparent_output_zat == 1);
    assert(review.sprout_joinsplits == 1);
    const uint8_t excessive[] = {1, 0x40, 7, 0x5a, 0xf0, 0x75, 7, 0};
    memcpy(wire + 10, excessive, sizeof excessive);
    assert(zcl_tx_review_parse(wire, sizeof wire, &review) < 0);
}

int main(void) {
    test_chain_coinbase();
    test_sapling_layout();
    test_rejections();
    test_public_value_and_sprout_layout();
    return 0;
}
