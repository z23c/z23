/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_screen.h"
#include "blue_review_protocol.h"
#include "zcl_address.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

static bool digest(const uint8_t *bytes, size_t length, uint8_t output[32]) {
    return SHA256(bytes, length, output) != NULL;
}

static void test_output_pages(void) {
    uint8_t wire[96] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    size_t length = 8;
    wire[length++] = 0;
    wire[length++] = 2;
    wire[length++] = 100;
    length += 7;
    wire[length++] = 25;
    wire[length++] = 0x76;
    wire[length++] = 0xa9;
    wire[length++] = 0x14;
    length += 20;
    wire[length++] = 0x88;
    wire[length++] = 0xac;
    length += 8;
    wire[length++] = 2;
    wire[length++] = 0x6a;
    wire[length++] = 0;
    length += 4 + 4 + 8 + 1 + 1 + 1;
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE];
    char address[ZCL_ADDRESS_SIZE];
    assert(zcl_address_from_hash160((const uint8_t[20]){0}, false,
                                    address) == 0);
    assert(blue_review_screen_output(wire, length, 0, digest, lines));
    assert(strcmp(lines[0], "OUTPUT 1/2: P2PKH") == 0);
    assert(strcmp(lines[1], "AMOUNT: 0.00000100 ZCL") == 0);
    assert(strcmp(lines[2], "ZCL MAINNET ADDRESS") == 0);
    char displayed[40];
    int written = snprintf(displayed, sizeof displayed, "%.*s%.*s",
        (int)sizeof lines[3], lines[3], (int)sizeof lines[4], lines[4]);
    assert(written >= 0 && (size_t)written < sizeof displayed);
    assert(strcmp(displayed, address) == 0);
    assert(strcmp(lines[5], "READ ONLY; NO SIGNING") == 0);
    assert(blue_review_screen_output(wire, length, 1, digest, lines));
    assert(strcmp(lines[0], "OUTPUT 2/2: OP_RETURN") == 0);
    assert(strcmp(lines[1], "AMOUNT: 0.00000000 ZCL") == 0);
    assert(strcmp(lines[2], "SCRIPT BYTES: 2") == 0);
    uint8_t script_digest[32];
    static const char hex[] = "0123456789abcdef";
    assert(digest((const uint8_t[]){0x6a, 0}, 2, script_digest));
    assert(strncmp(lines[3], "SHA256: ", 8) == 0);
    for (unsigned i = 0; i < 10; ++i) {
        assert(lines[3][8 + 2 * i] == hex[script_digest[i] >> 4]);
        assert(lines[3][9 + 2 * i] == hex[script_digest[i] & 15]);
    }
    assert(strcmp(lines[4], "TOKEN STATUS UNVERIFIED") == 0);
    wire[18] = 23;
    wire[19] = 0xa9;
    wire[20] = 0x14;
    wire[21] = 0;
    wire[41] = 0x87;
    memmove(wire + 42, wire + 44, length - 44);
    length -= 2;
    assert(zcl_address_from_hash160((const uint8_t[20]){0}, true,
                                    address) == 0);
    assert(blue_review_screen_output(wire, length, 0, digest, lines));
    assert(strcmp(lines[0], "OUTPUT 1/2: P2SH") == 0);
    written = snprintf(displayed, sizeof displayed, "%.*s%.*s",
        (int)sizeof lines[3], lines[3], (int)sizeof lines[4], lines[4]);
    assert(written >= 0 && (size_t)written < sizeof displayed);
    assert(strcmp(displayed, address) == 0);
    assert(!blue_review_screen_output(wire, length, 2, digest, lines));
    assert(!blue_review_screen_output(wire, length - 1, 0, digest, lines));
    assert(!blue_review_screen_output(NULL, length, 0, digest, lines));
}

int main(void) {
    test_output_pages();
    zcl_tx_review review = {
        .transparent_inputs = 2, .transparent_outputs = 3,
        .sapling_spends = 1, .sapling_outputs = 4,
        .sprout_joinsplits = 0, .transparent_output_zat = 39062500
    };
    uint8_t reply[76] = {0};
    blue_review_encode_summary(&review, reply);
    memcpy(reply + 44, (const uint8_t[]){0x63, 0xd1, 0x85, 0x34,
                                       0xde, 0x5f, 0x2d, 0x1c}, 8);
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE];
    assert(blue_review_screen_format(reply, lines));
    assert(strcmp(lines[0], "PUBLIC IN/OUT: 2/3") == 0);
    assert(strcmp(lines[1], "PUB OUT: 0.39062500 ZCL") == 0);
    assert(strcmp(lines[2], "SHIELDED SPEND/OUT: 1/4") == 0);
    assert(strcmp(lines[3], "FEE UNKNOWN; SPROUT: 0") == 0);
    assert(strcmp(lines[4], "SHIELDED HIDDEN; NO SIGNING") == 0);
    assert(strcmp(lines[5], "TX SHA256: 63d18534de5f2d1c") == 0);
    assert(!blue_review_screen_format(NULL, lines));
    assert(!blue_review_screen_format(reply, NULL));
    review.transparent_output_zat = 2100000000000000ULL;
    blue_review_encode_summary(&review, reply);
    assert(blue_review_screen_format(reply, lines));
    assert(strcmp(lines[1], "PUB OUT: 21000000.00000000 ZCL") == 0);
    return 0;
}
