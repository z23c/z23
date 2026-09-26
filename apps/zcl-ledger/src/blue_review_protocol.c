/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_protocol.h"
#include "zcl_tx_review.h"

#include <string.h>

static void put_u32(uint8_t *output, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) output[i] = (uint8_t)(value >> (8 * i));
}

static void put_u64(uint8_t *output, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) output[i] = (uint8_t)(value >> (8 * i));
}

void blue_review_encode_summary(const zcl_tx_review *review,
                                uint8_t reply[44]) {
    put_u32(reply, review->transparent_inputs);
    put_u32(reply + 4, review->transparent_outputs);
    put_u32(reply + 8, review->sapling_spends);
    put_u32(reply + 12, review->sapling_outputs);
    put_u32(reply + 16, review->sprout_joinsplits);
    put_u64(reply + 20, review->transparent_output_zat);
    put_u64(reply + 28, (uint64_t)review->value_balance_zat);
    put_u32(reply + 36, review->lock_time);
    put_u32(reply + 40, review->expiry_height);
}

static uint16_t begin_review(blue_review_state *state, const uint8_t *data,
                             size_t length) {
    state->expected = state->received = 0;
    if (length != 2) return 0x6700;
    uint16_t expected = (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
    if (expected < 29 || expected > ZCL_BLUE_REVIEW_MAX_BYTES) return 0x6a80;
    state->expected = expected;
    return 0x9000;
}

static uint16_t append_chunk(blue_review_state *state, const uint8_t *data,
                              size_t length) {
    if (state->expected == 0) return 0x6985;
    if (length == 0 || length > (size_t)(state->expected - state->received)) {
        state->expected = state->received = 0;
        return 0x6a80;
    }
    memcpy(state->wire + state->received, data, length);
    state->received = (uint16_t)(state->received + length);
    return 0x9000;
}

static uint16_t finish_review(blue_review_state *state, size_t length,
                              uint8_t *reply, size_t capacity,
                              size_t *reply_length) {
    if (length != 0) return 0x6700;
    if (!state->expected || state->received != state->expected) return 0x6985;
    zcl_tx_review review;
    int parsed = zcl_tx_review_parse(state->wire, state->received, &review);
    state->expected = state->received = 0;
    if (parsed < 0) return 0x6a80;
    if (capacity < 44) return 0x6700;
    blue_review_encode_summary(&review, reply);
    *reply_length = 44;
    return 0x9000;
}

static uint16_t identify(size_t length, uint8_t *reply, size_t capacity,
                         size_t *reply_length) {
    if (length || capacity < 5) return 0x6700;
    memcpy(reply, "ZCL", 3);
    reply[3] = 4;
    reply[4] = 0x40;
    *reply_length = 5;
    return 0x9000;
}

static uint16_t clear_review(blue_review_state *state, size_t length) {
    if (length) return 0x6700;
    state->expected = state->received = 0;
    return 0x9000;
}

uint16_t blue_review_handle(blue_review_state *state,
                            const uint8_t *apdu, size_t apdu_length,
                            uint8_t *reply, size_t reply_capacity,
                            size_t *reply_length) {
    if (!state || !apdu || !reply || !reply_length) return 0x6a80;
    *reply_length = 0;
    if (apdu_length < 5 || apdu_length != 5 + (size_t)apdu[4]) return 0x6700;
    if (apdu[0] != 0xa5) return 0x6e00;
    if (apdu[2] != 0 || apdu[3] != 0) return 0x6b00;
    const uint8_t *data = apdu + 5;
    size_t length = apdu[4];
    switch (apdu[1]) {
    case 0x01: return identify(length, reply, reply_capacity, reply_length);
    case 0x10: return begin_review(state, data, length);
    case 0x11: return append_chunk(state, data, length);
    case 0x12: return finish_review(state, length, reply,
                                    reply_capacity, reply_length);
    case 0x13: return clear_review(state, length);
    default: return 0x6d00;
    }
}
