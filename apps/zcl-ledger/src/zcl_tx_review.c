/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_review.h"

#include <stdbool.h>

enum { ZCL_MAX_MONEY_ZAT = 2100000000000000ULL };

typedef struct {
    const uint8_t *wire;
    size_t length;
    size_t offset;
} cursor;

static bool take(cursor *input, size_t count, const uint8_t **bytes) {
    if (count > input->length - input->offset) return false;
    *bytes = input->wire + input->offset;
    input->offset += count;
    return true;
}

static bool read_u32(cursor *input, uint32_t *value) {
    const uint8_t *bytes;
    if (!take(input, 4, &bytes)) return false;
    *value = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
             ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
    return true;
}

static bool read_u64(cursor *input, uint64_t *value) {
    const uint8_t *bytes;
    if (!take(input, 8, &bytes)) return false;
    *value = 0;
    for (unsigned i = 0; i < 8; ++i) *value |= (uint64_t)bytes[i] << (8 * i);
    return true;
}

static bool compact_size(cursor *input, uint64_t *value) {
    const uint8_t *prefix;
    if (!take(input, 1, &prefix)) return false;
    if (prefix[0] < 0xfd) { *value = prefix[0]; return true; }
    const uint8_t *bytes;
    size_t width = prefix[0] == 0xfd ? 2 : prefix[0] == 0xfe ? 4 : 8;
    if (!take(input, width, &bytes)) return false;
    uint64_t result = 0;
    for (size_t i = 0; i < width; ++i) result |= (uint64_t)bytes[i] << (8 * i);
    if ((width == 2 && result < 0xfd) ||
        (width == 4 && result <= UINT16_MAX) ||
        (width == 8 && result <= UINT32_MAX)) return false;
    *value = result;
    return true;
}

static bool skip_script(cursor *input) {
    uint64_t length;
    const uint8_t *bytes;
    return compact_size(input, &length) &&
           length <= input->length - input->offset &&
           take(input, (size_t)length, &bytes);
}

static bool parse_inputs(cursor *input, zcl_tx_review *review) {
    uint64_t count;
    const uint8_t *bytes;
    if (!compact_size(input, &count) || count > 65536 ||
        count > (input->length - input->offset) / 41) return false;
    review->transparent_inputs = (uint32_t)count;
    for (uint64_t i = 0; i < count; ++i)
        if (!take(input, 36, &bytes) || !skip_script(input) ||
            !take(input, 4, &bytes)) return false;
    return true;
}

static bool parse_outputs(cursor *input, zcl_tx_review *review) {
    uint64_t count;
    if (!compact_size(input, &count) || count > 65536 ||
        count > (input->length - input->offset) / 9) return false;
    review->transparent_outputs = (uint32_t)count;
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t value;
        if (!read_u64(input, &value) || value > ZCL_MAX_MONEY_ZAT ||
            value > ZCL_MAX_MONEY_ZAT - review->transparent_output_zat ||
            !skip_script(input)) return false;
        review->transparent_output_zat += value;
    }
    return true;
}

static bool skip_fixed_vector(cursor *input, uint32_t *count_out,
                              uint64_t maximum, size_t item_size) {
    uint64_t count;
    const uint8_t *bytes;
    if (!compact_size(input, &count) || count > maximum ||
        count > (input->length - input->offset) / item_size ||
        !take(input, (size_t)count * item_size, &bytes)) return false;
    *count_out = (uint32_t)count;
    return true;
}

static bool parse_shielded(cursor *input, zcl_tx_review *review) {
    uint64_t balance;
    const uint8_t *bytes;
    if (!read_u64(input, &balance) ||
        (balance > ZCL_MAX_MONEY_ZAT &&
         balance < UINT64_MAX - ZCL_MAX_MONEY_ZAT + 1)) return false;
    review->value_balance_zat = balance <= ZCL_MAX_MONEY_ZAT
        ? (int64_t)balance : -(int64_t)(~balance + 1);
    if (!skip_fixed_vector(input, &review->sapling_spends, 4096, 384) ||
        !skip_fixed_vector(input, &review->sapling_outputs, 4096, 948) ||
        !skip_fixed_vector(input, &review->sprout_joinsplits, 4096, 1634))
        return false;
    if (review->sprout_joinsplits && !take(input, 96, &bytes)) return false;
    if ((review->sapling_spends || review->sapling_outputs) &&
        !take(input, 64, &bytes)) return false;
    return true;
}

int zcl_tx_review_parse(const uint8_t *wire, size_t length,
                        zcl_tx_review *review) {
    if (!wire || !review || length > ZCL_TX_REVIEW_MAX_BYTES) return -1;
    cursor input = {.wire = wire, .length = length};
    zcl_tx_review parsed = {0};
    uint32_t header, group;
    if (!read_u32(&input, &header) || header != 0x80000004 ||
        !read_u32(&input, &group) || group != 0x892f2085 ||
        !parse_inputs(&input, &parsed) || !parse_outputs(&input, &parsed) ||
        !read_u32(&input, &parsed.lock_time) ||
        !read_u32(&input, &parsed.expiry_height) ||
        !parse_shielded(&input, &parsed) || input.offset != length) return -1;
    *review = parsed;
    return 0;
}
