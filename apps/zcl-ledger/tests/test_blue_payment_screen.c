/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_payment_render.h"
#include "zcl_address.h"

#include <openssl/sha.h>

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool digest(const uint8_t *bytes, size_t length, uint8_t output[32]) {
    return SHA256(bytes, length, output) != NULL;
}

static bool reject_hash(const uint8_t *bytes, size_t length,
    uint8_t output[32]) {
    (void)bytes;
    (void)length;
    (void)output;
    return false;
}

static void check_address(const blue_payment_screen *screen,
    const char *expected) {
    char combined[40];
    int written = snprintf(combined, sizeof combined, "%.*s%.*s%.*s",
        (int)sizeof screen->address_lines[0], screen->address_lines[0],
        (int)sizeof screen->address_lines[1], screen->address_lines[1],
        (int)sizeof screen->address_lines[2], screen->address_lines[2]);
    assert(written >= 0 && (size_t)written < sizeof combined);
    assert(strlen(combined) == 35);
    assert(strcmp(combined, screen->address) == 0);
    assert(strcmp(combined, expected) == 0);
}

int main(int argc, char **argv) {
    struct {
        char text[BLUE_PAYMENT_AMOUNT_TEXT_SIZE];
        uint8_t guard;
    } amount = {.guard = 0xa5};
    assert(blue_payment_amount_text(2100000000000000ULL, amount.text));
    assert(strcmp(amount.text, "21000000.00000000 ZCL") == 0);
    assert(amount.guard == 0xa5);
    assert(!blue_payment_amount_text(2100000000000001ULL, amount.text));
    assert(strcmp(blue_payment_input_paths_label(
        BLUE_PAYMENT_INPUT_EXTERNAL), "INPUT EXT 0/0") == 0);
    assert(strcmp(blue_payment_input_paths_label(
        BLUE_PAYMENT_INPUT_INTERNAL), "INPUT INT 1/0") == 0);
    assert(strcmp(blue_payment_input_paths_label(
        BLUE_PAYMENT_INPUT_EXTERNAL | BLUE_PAYMENT_INPUT_INTERNAL),
        "INPUT 0/0 + 1/0") == 0);
    assert(blue_payment_input_paths_label(0) == NULL);
    assert(blue_payment_input_paths_label(4) == NULL);
    blue_payment_output output = {.index = 0,
        .amount_zat = 100000001, .type = ZCL_TX_STREAM_P2PKH};
    memset(output.hash160, 0x11, 20);
    blue_payment_screen screen;
    char expected[ZCL_ADDRESS_SIZE];
    uint8_t account_hash160[20], internal_hash160[20];
    memset(internal_hash160, 0x33, sizeof internal_hash160);
    memcpy(account_hash160, output.hash160, sizeof account_hash160);
    assert(blue_payment_account_classify(&output, account_hash160,
        internal_hash160, true) ==
           BLUE_PAYMENT_THIS_ACCOUNT);
    account_hash160[19] ^= 1;
    assert(blue_payment_account_classify(&output, account_hash160,
        internal_hash160, true) ==
           BLUE_PAYMENT_OTHER_P2PKH);
    account_hash160[19] ^= 1;
    assert(blue_payment_account_classify(&output, account_hash160,
        internal_hash160, false) ==
           BLUE_PAYMENT_ACCOUNT_UNKNOWN);
    assert(blue_payment_account_classify(NULL, account_hash160,
        internal_hash160, true) ==
           BLUE_PAYMENT_ACCOUNT_UNKNOWN);
    assert(zcl_address_from_hash160(output.hash160, false, expected) == 0);
    assert(blue_payment_screen_format(&output, 2, digest, &screen));
    assert(strcmp(screen.title, "OUTPUT 1/2") == 0);
    assert(strcmp(screen.amount, "1.00000001 ZCL") == 0);
    assert(strcmp(screen.kind, "P2PKH") == 0);
    check_address(&screen, expected);
    assert(blue_payment_screen_mark_account(&screen, &output,
        account_hash160, internal_hash160, true));
    assert(strcmp(screen.kind, "THIS ACCOUNT") == 0);
    if (argc >= 3) assert(blue_payment_render_png(argv[1], &screen, false));
    account_hash160[0] ^= 1;
    assert(blue_payment_screen_mark_account(&screen, &output,
        account_hash160, internal_hash160, true));
    assert(strcmp(screen.kind, "OTHER ADDRESS") == 0);
    account_hash160[0] ^= 1;
    memcpy(output.hash160, internal_hash160, sizeof output.hash160);
    assert(zcl_address_from_hash160(output.hash160, false, expected) == 0);
    assert(blue_payment_screen_format(&output, 2, digest, &screen));
    assert(blue_payment_screen_mark_account(&screen, &output,
        account_hash160, internal_hash160, true));
    assert(strcmp(screen.kind, "OWN INTERNAL 1/0") == 0);
    check_address(&screen, expected);
    if (argc >= 4) assert(blue_payment_render_png(argv[3], &screen, true));
    assert(!blue_payment_screen_mark_account(&screen, &output,
        account_hash160, NULL, true));
    assert(screen.kind[0] == 0);

    output.index = 1;
    output.amount_zat = 2100000000000000ULL;
    output.type = ZCL_TX_STREAM_P2SH;
    memset(output.hash160, 0x22, 20);
    memcpy(account_hash160, output.hash160, sizeof account_hash160);
    assert(blue_payment_account_classify(&output, account_hash160,
        internal_hash160, true) ==
           BLUE_PAYMENT_P2SH_ADDRESS);
    output.type = (zcl_tx_stream_output_type)99;
    assert(blue_payment_account_classify(&output, account_hash160,
        internal_hash160, true) ==
           BLUE_PAYMENT_ACCOUNT_UNKNOWN);
    output.type = ZCL_TX_STREAM_P2SH;
    assert(zcl_address_from_hash160(output.hash160, true, expected) == 0);
    assert(blue_payment_screen_format(&output, 2, digest, &screen));
    assert(strcmp(screen.title, "OUTPUT 2/2") == 0);
    assert(strcmp(screen.amount, "21000000.00000000 ZCL") == 0);
    assert(strcmp(screen.kind, "P2SH") == 0);
    check_address(&screen, expected);
    assert(blue_payment_screen_mark_account(&screen, &output,
        account_hash160, internal_hash160, true));
    assert(strcmp(screen.kind, "P2SH ADDRESS") == 0);
    if (argc >= 3) assert(blue_payment_render_png(argv[2], &screen, true));

    assert(!blue_payment_render_fee_png(NULL, 100000000,
        BLUE_PAYMENT_INPUT_EXTERNAL, true));
    assert(!blue_payment_render_fee_png("/tmp/invalid-fee.png", 100000000,
        0, true));
    assert(!blue_payment_render_fee_png("/tmp/invalid-fee.png",
        2100000000000001ULL, BLUE_PAYMENT_INPUT_EXTERNAL, true));
    if (argc >= 5) assert(blue_payment_render_fee_png(argv[4], 100000000,
        BLUE_PAYMENT_INPUT_EXTERNAL | BLUE_PAYMENT_INPUT_INTERNAL, true));
    assert(!blue_payment_render_totals_png(NULL, 300000000,
        100000000, 100000000, true));
    assert(!blue_payment_render_totals_png("/tmp/invalid-totals.png",
        100000000, 200000000, 100000000, true));
    if (argc >= 6) assert(blue_payment_render_totals_png(argv[5],
        300000000, 100000000, 100000000, true));

    assert(!blue_payment_screen_mark_account(&screen, NULL,
        account_hash160, internal_hash160, true));
    assert(screen.kind[0] == 0);

    assert(!blue_payment_screen_format(&output, 0, digest, &screen));
    assert(!blue_payment_screen_format(&output, 17, digest, &screen));
    assert(!blue_payment_screen_format(&output, 1, digest, &screen));
    output.amount_zat++;
    assert(!blue_payment_screen_format(&output, 2, digest, &screen));
    output.amount_zat--;
    assert(!blue_payment_screen_format(&output, 2, reject_hash, &screen));
    assert(screen.title[0] == 0 && screen.address[0] == 0);
    assert(!blue_payment_screen_format(NULL, 2, digest, &screen));
    assert(!blue_payment_render_png(NULL, &screen, false));
    return 0;
}
