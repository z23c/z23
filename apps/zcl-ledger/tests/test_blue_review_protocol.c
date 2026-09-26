/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_protocol.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static uint16_t call(blue_review_state *state, uint8_t *apdu, size_t length,
                     size_t *reply_length) {
    return blue_review_handle(state, apdu, length, apdu, 255, reply_length);
}

static void test_minimal_review(void) {
    blue_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x01};
    size_t reply_length = 0;
    assert(call(&state, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 5 && memcmp(apdu, "ZCL\x04\x40", 5) == 0);

    const uint8_t begin[] = {0xa5, 0x10, 0, 0, 2, 29, 0};
    memcpy(apdu, begin, sizeof begin);
    assert(call(&state, apdu, sizeof begin, &reply_length) == 0x9000);
    assert(reply_length == 0);
    const uint8_t header[] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    memset(apdu, 0, sizeof apdu);
    apdu[0] = 0xa5;
    apdu[1] = 0x11;
    apdu[4] = 29;
    memcpy(apdu + 5, header, sizeof header);
    assert(call(&state, apdu, 34, &reply_length) == 0x9000);
    apdu[1] = 0x12;
    apdu[4] = 0;
    assert(call(&state, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 44);
    for (size_t i = 0; i < reply_length; ++i) assert(apdu[i] == 0);
    assert(call(&state, apdu, 5, &reply_length) == 0x6e00);
}

static void test_state_and_bounds(void) {
    blue_review_state state = {0};
    uint8_t apdu[260] = {0xa5, 0x12};
    size_t reply_length = 9;
    assert(call(&state, apdu, 5, &reply_length) == 0x6985);
    assert(reply_length == 0);
    apdu[1] = 0x10;
    apdu[4] = 2;
    apdu[5] = 0;
    apdu[6] = 16;
    assert(call(&state, apdu, 7, &reply_length) == 0x9000);
    assert(state.expected == 4096);
    apdu[5] = 1;
    assert(call(&state, apdu, 7, &reply_length) == 0x6a80);
    assert(state.expected == 0);
    apdu[5] = 29;
    apdu[6] = 0;
    assert(call(&state, apdu, 7, &reply_length) == 0x9000);
    apdu[1] = 0x11;
    apdu[4] = 30;
    assert(call(&state, apdu, 35, &reply_length) == 0x6a80);
    assert(state.expected == 0);
    apdu[1] = 0x12;
    apdu[4] = 0;
    assert(call(&state, apdu, 5, &reply_length) == 0x6985);
    apdu[0] = 0;
    assert(call(&state, apdu, 5, &reply_length) == 0x6e00);
    assert(blue_review_handle(NULL, apdu, 5, apdu, 255,
                              &reply_length) == 0x6a80);
}

int main(void) {
    test_minimal_review();
    test_state_and_bounds();
    return 0;
}
