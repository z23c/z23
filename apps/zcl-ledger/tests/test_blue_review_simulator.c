/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_review_app.h"
#include "blue_review_accessible.h"
#include "blue_review_render.h"
#include "blue_review_screen.h"
#include "blue_review_simulate.h"
#include "blue_sapling_fixture.h"
#include "zcl_zip243_host.h"

#undef NDEBUG
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool sha256(const uint8_t *bytes, size_t length, uint8_t out[32]) {
    return SHA256(bytes, length, out) != NULL;
}

static int digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t read_fixture(const char *path, uint8_t wire[245]) {
    FILE *file = fopen(path, "r");
    assert(file);
    char line[512];
    do { assert(fgets(line, sizeof line, file)); } while (line[0] == '#');
    assert(strcspn(line, "\r\n") == 490);
    for (size_t i = 0; i < 245; ++i) {
        int high = digit(line[i * 2]), low = digit(line[i * 2 + 1]);
        assert(high >= 0 && low >= 0);
        wire[i] = (uint8_t)((high << 4) | low);
    }
    assert(!ferror(file) && fclose(file) == 0);
    return 245;
}

static uint16_t command(blue_review_app *app, uint8_t apdu[260],
                        size_t length, size_t *reply_length) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    return blue_review_app_command(app, apdu, length, apdu, 255,
                                   reply_length, sha256, &hasher);
}

static void expect_screen(const blue_review_app *app, const char *first) {
    assert(strcmp(app->lines[0], first) == 0);
    for (size_t i = 0; i < ZCL_BLUE_REVIEW_LINES; ++i)
        printf("%s\n", app->lines[i]);
    puts("");
}

static void simulate(const uint8_t *wire, size_t length) {
    blue_review_app app = {0};
    uint8_t apdu[260] = {0xa5, 0x01, 0, 0, 0};
    size_t reply_length = 0;
    blue_review_app_reset(&app);
    expect_screen(&app, "CONNECT Z23");
    blue_review_app_toggle_text(&app);
    for (unsigned detail = 1; detail < 5; ++detail) {
        assert(blue_review_app_advance(&app, sha256));
        assert(app.detail == detail);
    }
    assert(blue_review_app_advance(&app, sha256));
    assert(app.detail == 0);
    blue_review_app_toggle_text(&app);
    assert(!blue_review_app_next(&app, sha256));
    assert(command(&app, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 5 && memcmp(apdu, "ZCL\x06\x40", 5) == 0);
    memcpy(apdu, (uint8_t[]){0xa5, 0x10, 0, 0, 2,
                            (uint8_t)length, (uint8_t)(length >> 8)}, 7);
    assert(command(&app, apdu, 7, &reply_length) == 0x9000);
    for (size_t offset = 0; offset < length; offset += 220) {
        size_t count = length - offset < 220 ? length - offset : 220;
        apdu[0] = 0xa5;
        apdu[1] = 0x11;
        apdu[2] = apdu[3] = 0;
        apdu[4] = (uint8_t)count;
        memcpy(apdu + 5, wire + offset, count);
        assert(command(&app, apdu, 5 + count, &reply_length) == 0x9000);
    }
    assert(!blue_review_app_next(&app, sha256));
    expect_screen(&app, "CONNECT Z23");
    memcpy(apdu, (uint8_t[]){0xa5, 0x14, 0, 0, 4,
                            0xbb, 0x09, 0xb8, 0x76}, 9);
    assert(command(&app, apdu, 9, &reply_length) == 0x9000);
    assert(reply_length == 32);
    memcpy(apdu, (uint8_t[]){0xa5, 0x12, 0, 0, 0}, 5);
    assert(command(&app, apdu, 5, &reply_length) == 0x9000);
    assert(reply_length == 76 && app.transaction.reviewed_length == length);
    assert(blue_review_app_next(&app, sha256));
    expect_screen(&app, "PUBLIC IN/OUT: 1/2");
    assert(strcmp(app.lines[1], "PUB OUT: 0.49999755 ZCL") == 0);
    assert(strcmp(app.lines[3], "FEE UNKNOWN; SPROUT: 0") == 0);
    assert(strcmp(app.lines[4], "SHIELDED HIDDEN; NO SIGNING") == 0);
    blue_review_app_toggle_text(&app);
    assert(app.large_text && app.detail == 0);
    blue_review_app_toggle_dark(&app);
    assert(app.dark);
    for (unsigned detail = 1; detail < ZCL_BLUE_REVIEW_LINES; ++detail) {
        assert(blue_review_app_advance(&app, sha256));
        assert(app.detail == detail);
        assert(strcmp(app.lines[0], "PUBLIC IN/OUT: 1/2") == 0);
    }
    assert(blue_review_app_advance(&app, sha256));
    assert(app.detail == 0);
    expect_screen(&app, "OUTPUT 1/2: P2PKH");
    blue_review_app_toggle_text(&app);
    assert(!app.large_text && app.detail == 0);
    blue_review_app_toggle_dark(&app);
    assert(!app.dark);
    assert(blue_review_app_next(&app, sha256));
    expect_screen(&app, "OUTPUT 2/2: P2PKH");
    assert(blue_review_app_next(&app, sha256));
    expect_screen(&app, "PUBLIC IN/OUT: 1/2");
    memcpy(apdu, (uint8_t[]){0xa5, 0x13, 0, 0, 0}, 5);
    assert(command(&app, apdu, 5, &reply_length) == 0x9000);
    expect_screen(&app, "CONNECT Z23");
    assert(!blue_review_app_next(&app, sha256));
    for (size_t i = 0; i < sizeof app.transaction.wire; ++i)
        assert(app.transaction.wire[i] == 0);
}

static void test_accessible_wrap(void) {
    char wrapped[40];
    assert(blue_review_accessible_wrap(
        "SHIELDED HIDDEN; NO SIGNING", wrapped));
    assert(strcmp(wrapped, "SHIELDED HIDDEN; NO\nSIGNING") == 0);
    assert(blue_review_accessible_wrap(
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", wrapped));
    char restored[32];
    size_t used = 0;
    for (const char *p = wrapped; *p; ++p)
        if (*p != '\n') restored[used++] = *p;
    restored[used] = 0;
    assert(strcmp(restored, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX") == 0);
    assert(!blue_review_accessible_wrap("\x01", wrapped));
    blue_review_app app = {0};
    blue_review_app_reset(&app);
    int written = snprintf(app.lines[0], sizeof app.lines[0], "%s",
                           "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW");
    assert(written == 31);
    char path[96];
    assert(snprintf(path, sizeof path, "/tmp/zcl-accessible-%ld.png",
                    (long)getpid()) > 0);
    assert(blue_review_render_preview_png(path, &app, true, 0));
    assert(unlink(path) == 0);
}

static void test_max_public_output_render(void) {
    uint8_t reply[76] = {0};
    uint64_t amount = UINT64_C(2100000000000000);
    for (unsigned i = 0; i < 8; ++i)
        reply[20 + i] = (uint8_t)(amount >> (8 * i));
    char lines[ZCL_BLUE_REVIEW_LINES][ZCL_BLUE_REVIEW_LINE_SIZE];
    assert(blue_review_screen_format(reply, lines));
    assert(strcmp(lines[1], "PUB OUT: 21000000.00000000 ZCL") == 0);
    char path[96];
    assert(snprintf(path, sizeof path, "/tmp/zcl-max-output-%ld.png",
                    (long)getpid()) > 0);
    assert(blue_review_render_lines_png(path, lines,
        "ZCL Shielded", "NEXT / REFRESH", false, -1));
    assert(blue_review_render_lines_png(path, lines,
        "ZCL Shielded", "NEXT / REFRESH", true, 1));
    assert(unlink(path) == 0);
}

static size_t script_fixture(uint8_t wire[96]) {
    memset(wire, 0, 96);
    memcpy(wire, (uint8_t[]){4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89}, 8);
    size_t length = 8;
    wire[length++] = 0;
    wire[length++] = 2;
    wire[length++] = 100;
    length += 7;
    wire[length++] = 23;
    wire[length++] = 0xa9;
    wire[length++] = 0x14;
    length += 20;
    wire[length++] = 0x87;
    length += 8;
    wire[length++] = 2;
    wire[length++] = 0x6a;
    wire[length++] = 0;
    length += 4 + 4 + 8 + 1 + 1 + 1;
    return length;
}

static void simulate_scripts(void) {
    blue_review_app app = {0};
    uint8_t wire[96], apdu[260];
    size_t length = script_fixture(wire), reply_length;
    blue_review_app_reset(&app);
    memcpy(apdu, (uint8_t[]){0xa5, 0x10, 0, 0, 2,
                            (uint8_t)length, 0}, 7);
    assert(command(&app, apdu, 7, &reply_length) == 0x9000);
    apdu[1] = 0x11;
    apdu[4] = (uint8_t)length;
    memcpy(apdu + 5, wire, length);
    assert(command(&app, apdu, length + 5, &reply_length) == 0x9000);
    memcpy(apdu, (uint8_t[]){0xa5, 0x12, 0, 0, 0}, 5);
    assert(command(&app, apdu, 5, &reply_length) == 0x9000);
    assert(blue_review_app_next(&app, sha256));
    assert(blue_review_app_next(&app, sha256));
    expect_screen(&app, "OUTPUT 1/2: P2SH");
    assert(strcmp(app.lines[2], "ZCL MAINNET ADDRESS") == 0);
    assert(blue_review_app_next(&app, sha256));
    expect_screen(&app, "OUTPUT 2/2: OP_RETURN");
    assert(strcmp(app.lines[4], "TOKEN STATUS UNVERIFIED") == 0);
}

static void simulate_rejected_review(void) {
    blue_review_app app = {0};
    uint8_t apdu[260] = {0xa5, 0x10, 0, 0, 2, 29, 0};
    size_t reply_length = 0;
    blue_review_app_reset(&app);
    assert(command(&app, apdu, 7, &reply_length) == 0x9000);
    memcpy(apdu, (uint8_t[]){0xa5, 0x11, 0, 0, 8,
                            4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89}, 13);
    assert(command(&app, apdu, 13, &reply_length) == 0x9000);
    int written = snprintf(app.lines[0], sizeof app.lines[0], "%s", "UPLOADING");
    assert(written == 9);
    apdu[4] = 9;
    assert(command(&app, apdu, 13, &reply_length) == 0x6700);
    assert(reply_length == 0);
    assert(app.transaction.expected == 0);
    assert(app.transaction.received == 0);
    assert(app.transaction.wire[3] == 0);
    assert(strcmp(app.lines[0], "CONNECT Z23") == 0);
}

static bool shielded_page(const blue_review_app *app, void *context) {
    unsigned *pages = context;
    ++*pages;
    if (*pages == 1) return strcmp(app->lines[0], "CONNECT Z23") == 0;
    return strcmp(app->lines[0], "PUBLIC IN/OUT: 0/0") == 0 &&
        strcmp(app->lines[2], "SHIELDED SPEND/OUT: 1/1") == 0 &&
        strcmp(app->lines[3], "FEE UNKNOWN; SPROUT: 0") == 0 &&
        strcmp(app->lines[4], "SHIELDED HIDDEN; NO SIGNING") == 0;
}

static void simulate_shielded_fixture(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    zcl_tx_review review;
    assert(zcl_tx_review_parse(wire, sizeof wire, &review) == 0);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    uint8_t digest[32];
    assert(zcl_zip243_shielded_digest(wire, sizeof wire, 0x76b809bb,
        &hasher, digest) == 0);
    assert(blue_review_simulate(wire, sizeof wire, &review, true,
        0x76b809bb, digest));
    unsigned pages = 0;
    assert(blue_review_simulate_pages(wire, sizeof wire, &review,
        shielded_page, &pages));
    assert(pages == 3);
}

static void simulate_interrupted_shielded(void) {
    uint8_t wire[BLUE_SYNTHETIC_SAPLING_BYTES];
    blue_sapling_fixture(wire);
    blue_review_app app = {0};
    uint8_t apdu[260] = {0xa5, 0x10, 0, 0, 2,
        (uint8_t)sizeof wire, (uint8_t)(sizeof wire >> 8)};
    size_t reply_length = 0;
    blue_review_app_reset(&app);
    assert(command(&app, apdu, 7, &reply_length) == 0x9000);
    apdu[1] = 0x11;
    apdu[4] = 220;
    memcpy(apdu + 5, wire, 220);
    assert(command(&app, apdu, 225, &reply_length) == 0x9000);
    assert(app.transaction.received == 220);
    apdu[4] = 219;
    assert(command(&app, apdu, 225, &reply_length) == 0x6700);
    assert(app.transaction.received == 0);
    for (size_t i = 0; i < sizeof app.transaction.wire; ++i)
        assert(app.transaction.wire[i] == 0);
    assert(strcmp(app.lines[0], "CONNECT Z23") == 0);
    memcpy(apdu, (uint8_t[]){0xa5, 0x14, 0, 0, 4,
        0xbb, 0x09, 0xb8, 0x76}, 9);
    assert(command(&app, apdu, 9, &reply_length) == 0x6985);
}

static uint32_t random_word(uint32_t *state) {
    *state = *state * 1664525u + 1013904223u;
    return *state;
}

static void simulate_malformed_commands(void) {
    blue_review_app app = {0};
    uint32_t seed = 0x2345abcd;
    static const uint8_t instructions[] = {1, 0x10, 0x11, 0x12,
                                           0x13, 0x14, 0xff};
    blue_review_app_reset(&app);
    for (unsigned trial = 0; trial < 10000; ++trial) {
        uint8_t apdu[260];
        for (size_t i = 0; i < sizeof apdu; ++i)
            apdu[i] = (uint8_t)(random_word(&seed) >> 24);
        apdu[0] = trial % 7 ? 0xa5 : apdu[0];
        apdu[1] = instructions[random_word(&seed) % sizeof instructions];
        if (trial % 5) apdu[2] = apdu[3] = 0;
        size_t length = random_word(&seed) % (sizeof apdu + 1);
        if (trial % 3 == 0 && length >= 5) apdu[4] = (uint8_t)(length - 5);
        size_t reply_length = 260;
        uint16_t status = command(&app, apdu, length, &reply_length);
        assert(status != 0 && reply_length <= 255);
        assert(app.transaction.expected <= ZCL_BLUE_REVIEW_MAX_BYTES);
        assert(app.transaction.received <= app.transaction.expected);
        assert(app.transaction.reviewed_length <= ZCL_BLUE_REVIEW_MAX_BYTES);
        if (trial % 11 == 0) blue_review_app_next(&app, sha256);
        for (size_t i = 0; i < ZCL_BLUE_REVIEW_LINES; ++i)
            assert(memchr(app.lines[i], 0, ZCL_BLUE_REVIEW_LINE_SIZE));
    }
}

int main(int argc, char **argv) {
    assert(argc == 2);
    uint8_t wire[245];
    size_t length = read_fixture(argv[1], wire);
    simulate(wire, length);
    zcl_tx_review review;
    assert(zcl_tx_review_parse(wire, length, &review) == 0);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    uint8_t digest[32];
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      &hasher, digest) == 0);
    assert(blue_review_simulate(wire, length, &review, true,
                                0x76b809bb, digest));
    assert(blue_review_simulate(wire, length, &review, false, 0, NULL));
    digest[0] ^= 1;
    assert(!blue_review_simulate(wire, length, &review, true,
                                 0x76b809bb, digest));
    simulate_scripts();
    simulate_rejected_review();
    simulate_shielded_fixture();
    simulate_interrupted_shielded();
    simulate_malformed_commands();
    test_accessible_wrap();
    test_max_public_output_render();
    return 0;
}
