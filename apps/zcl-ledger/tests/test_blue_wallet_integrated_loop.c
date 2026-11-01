/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zsha256/zsha256.h"
#include "zripemd/zripemd.h"
#include "blue_host_gui.h"
#include "blue_install_params.h"
#include "blue_payment_fixture.h"
#include "blue_payment_live.h"
#include "zcl_zip243_host.h"

#include <stddef.h>
#include <stdio.h>

#undef NDEBUG
#include <assert.h>
#include <setjmp.h>
#include <string.h>

#define main blue_wallet_device_main
#include "../device-blue-wallet/src/main.c"
#undef main
#include "../device-blue-wallet/src/wallet_payment_device.c"

unsigned char G_io_apdu_buffer[260];
unsigned blue_wallet_test_tick_ms;
static blue_try_context *active_try;
static jmp_buf request_boundary;
static const bagl_element_t *shown;
static size_t shown_count, replies;
static unsigned exits, signer_wipes;
static bool request_sent, pin_valid = true;
static uint8_t request[260], response[260];
static size_t request_length, response_length;
static uint8_t signed_digest[32], signed_path;
static unsigned sign_calls;
static bool reset_during_blake_init;
static unsigned signer_interrupt;
static char observed_recipient[40];
static char observed_amount[32];

/* Append one address line to out (holding `used` bytes), asserting that it fits. */
static size_t append_address_line(char *out, size_t out_size, size_t used,
    const char *line, size_t line_size) {
    size_t length = strnlen(line, line_size);
    assert(length < out_size - used);
    memcpy(out + used, line, length);
    out[used + length] = 0;
    return used + length;
}
static const uint8_t fixture_digest[32] = {
    0xbc, 0x49, 0xff, 0x23, 0x8f, 0xbb, 0x4a, 0x74,
    0x67, 0xfd, 0x9c, 0x4e, 0x30, 0xad, 0x85, 0xa2,
    0x5c, 0x80, 0x54, 0x5e, 0xa7, 0xcc, 0xf8, 0xc4,
    0x4d, 0x27, 0xe4, 0x18, 0xb8, 0x13, 0x28, 0x4b
};

void blue_try_enter(blue_try_context *context) {
    context->code = 0;
    context->previous = active_try;
    active_try = context;
}

void blue_try_leave(void) {
    assert(active_try);
    active_try = active_try->previous;
}

blue_try_context *blue_try_current(void) { return active_try; }

void blue_throw(unsigned error) {
    assert(active_try && error);
    active_try->code = error;
    longjmp(active_try->jump, 1);
}

void blue_wallet_test_display(const bagl_element_t *elements, size_t count,
    unsigned int (*button)(unsigned int, unsigned int)) {
    assert(button && button(0, 0) == 0);
    shown = elements;
    shown_count = count;
}

void blue_wallet_test_set_interval(unsigned ms) {
    blue_wallet_test_tick_ms = ms;
}

void blue_wallet_test_finger(const unsigned char *buffer) {
    if (buffer[3] != SEPROXYHAL_TAG_FINGER_EVENT_RELEASE) return;
    unsigned x = ((unsigned)buffer[4] << 8) | buffer[5];
    unsigned y = ((unsigned)buffer[6] << 8) | buffer[7];
    for (size_t i = 0; i < shown_count; ++i) {
        const bagl_element_t *element = &shown[i];
        if (!(element->component.type & BAGL_FLAG_TOUCHABLE) ||
            !element->tap) continue;
        if (x >= (unsigned)element->component.x &&
            x < (unsigned)(element->component.x + element->component.width) &&
            y >= (unsigned)element->component.y &&
            y < (unsigned)(element->component.y + element->component.height)) {
            (void)element->tap(element);
            return;
        }
    }
}

static void finger_event(unsigned x, unsigned y, unsigned kind) {
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_FINGER_EVENT;
    G_io_seproxyhal_spi_buffer[3] = (uint8_t)kind;
    G_io_seproxyhal_spi_buffer[4] = (uint8_t)(x >> 8);
    G_io_seproxyhal_spi_buffer[5] = (uint8_t)x;
    G_io_seproxyhal_spi_buffer[6] = (uint8_t)(y >> 8);
    G_io_seproxyhal_spi_buffer[7] = (uint8_t)y;
    (void)io_event(CHANNEL_SPI);
}

static void finger_release(unsigned x, unsigned y) {
    finger_event(x, y, SEPROXYHAL_TAG_FINGER_EVENT_RELEASE);
}

static void finger_tap(unsigned x, unsigned y) {
    finger_event(x, y, SEPROXYHAL_TAG_FINGER_EVENT_TOUCH);
    finger_release(x, y);
}

static const bagl_element_t *find_text(const char *text) {
    for (size_t i = 0; i < shown_count; ++i)
        if (shown[i].text && strcmp(shown[i].text, text) == 0)
            return &shown[i];
    return NULL;
}

static void tap_exit(void) {
    const bagl_element_t *element = find_text("EXIT");
    assert(element && element->tap);
    finger_tap((unsigned)element->component.x +
        (unsigned)element->component.width / 2,
        (unsigned)element->component.y +
        (unsigned)element->component.height / 2);
}

static void tap_text(const char *text) {
    const bagl_element_t *element = find_text(text);
    assert(element && element->tap);
    finger_tap((unsigned)element->component.x +
        (unsigned)element->component.width / 2,
        (unsigned)element->component.y +
        (unsigned)element->component.height / 2);
}

int os_global_pin_is_validated(void) { return pin_valid; }

void os_perso_derive_node_bip32(unsigned curve, const unsigned *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]) {
    assert(curve == CX_CURVE_256K1 && length == 5 && path[3] <= 1);
    memset(raw, path[3] ? 0x22 : 0x11, 32);
    memset(chain, 0x33, 32);
}

int cx_ecfp_init_private_key(unsigned curve, const uint8_t raw[32],
    unsigned length, cx_ecfp_private_key_t *key) {
    assert(curve == CX_CURVE_256K1 && length == 32);
    key->curve = curve;
    key->d_len = length;
    memcpy(key->d, raw, length);
    return 0;
}

int cx_ecfp_generate_pair(unsigned curve, cx_ecfp_public_key_t *public_key,
    cx_ecfp_private_key_t *private_key, int keepprivate) {
    assert(curve == CX_CURVE_256K1 && keepprivate == 1);
    public_key->curve = curve;
    public_key->W_len = 65;
    public_key->W[0] = 4;
    memcpy(public_key->W + 1, private_key->d, 32);
    memset(public_key->W + 33, private_key->d[0] + 1, 32);
    return 0;
}

int cx_hash_sha256(const uint8_t *bytes, unsigned length, uint8_t digest[32]) {
    zsha256(bytes, length, digest);
    return 32;
}

int cx_ripemd160_init(cx_ripemd160_t *context) {
    context->header = CX_RIPEMD160;
    return CX_RIPEMD160;
}

int cx_hash5(void *context, unsigned mode, const uint8_t *bytes,
    unsigned length, uint8_t *digest) {
    assert(((cx_ripemd160_t *)context)->header == CX_RIPEMD160);
    assert(mode == CX_LAST);
    zripemd160(bytes, length, digest);
    return 20;
}

int cx_blake2b_init2(void *context, unsigned bits, const void *key,
    size_t key_length, const uint8_t *personal, size_t personal_length) {
    assert(bits == 256 && key_length == 0 && personal_length == 16);
    int initialized = blake2b_init_salt_personal(context, 32, key,
        key_length, NULL, personal);
    if (reset_during_blake_init) {
        reset_during_blake_init = false;
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
        G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_RESET;
        (void)io_event(CHANNEL_SPI);
    }
    return initialized == 0 ? CX_BLAKE2B : 0;
}

int cx_sha256_init(void *context) {
    zsha256_init(context);
    return CX_SHA256;
}

int (cx_hash)(void *context, unsigned mode, const uint8_t *bytes,
    unsigned length, uint8_t *digest, unsigned digest_length) {
    if (context == &payment_blake) {
        if (mode == CX_LAST) {
            assert(digest && digest_length == 32);
            return blake2b_final(context, digest, 32) == 0 ? 32 : -1;
        }
        assert(!digest && !digest_length);
        return blake2b_update(context, bytes, length);
    }
    assert(context == &payment_sha);
    if (mode == CX_LAST) {
        assert(digest && digest_length == 32);
        zsha256_final(context, digest);
        return 32;
    }
    assert(!digest && !digest_length);
    zsha256_update(context, bytes, length);
    return 0;
}

bool blue_wallet_sign_digest(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length) {
    (void)context;
    /* This test signer captures the reviewed digest; its DER is not ECDSA. */
    static const uint8_t test_der[8] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
    };
    assert(path == BLUE_PAYMENT_INPUT_EXTERNAL && digest && public_key &&
        signature && signature_length);
    ++sign_calls;
    signed_path = path;
    memcpy(signed_digest, digest, sizeof signed_digest);
    if (signer_interrupt) {
        unsigned interrupt = signer_interrupt;
        signer_interrupt = 0;
        unsigned before = signer_wipes;
        G_io_seproxyhal_spi_buffer[0] = interrupt == 1 ?
            SEPROXYHAL_TAG_USB_EVENT : SEPROXYHAL_TAG_TICKER_EVENT;
        G_io_seproxyhal_spi_buffer[3] = interrupt == 1 ?
            SEPROXYHAL_TAG_USB_EVENT_RESET : 0;
        (void)io_event(CHANNEL_SPI);
        assert(signer_wipes == before);
    }
    public_key[0] = 2;
    memset(public_key + 1, 0x11, 32);
    memcpy(signature, test_der, sizeof test_der);
    *signature_length = sizeof test_der;
    return true;
}

void blue_wallet_signer_wipe(void) { ++signer_wipes; }
void os_boot(void) {}
void io_seproxyhal_init(void) {}
void USB_power(int enabled) { assert(enabled == 0 || enabled == 1); }
void os_sched_exit(unsigned code) { assert(code == 0); ++exits; }

unsigned short io_exchange(unsigned char channel, unsigned short tx_length) {
    if (tx_length) {
        assert(channel == (CHANNEL_APDU | IO_RETURN_AFTER_TX));
        assert(tx_length >= 2 && tx_length <= sizeof response);
        memcpy(response, G_io_apdu_buffer, tx_length);
        response_length = tx_length;
        ++replies;
        return 0;
    }
    assert(channel == CHANNEL_APDU);
    if (request_sent) longjmp(request_boundary, 1);
    assert(request_length && request_length <= sizeof G_io_apdu_buffer);
    memcpy(G_io_apdu_buffer, request, request_length);
    request_sent = true;
    return (unsigned short)request_length;
}

void io_seproxyhal_spi_send(const unsigned char *bytes,
    unsigned short length) { (void)bytes; (void)length; assert(false); }
unsigned short io_seproxyhal_spi_recv(unsigned char *bytes,
    unsigned short capacity, int flags) {
    (void)bytes; (void)capacity; (void)flags; assert(false); return 0;
}
void io_seproxyhal_display_default(bagl_element_t *element) {
    (void)element; assert(false);
}
int io_seproxyhal_spi_is_status_sent(void) { return 1; }
void io_seproxyhal_general_status(void) { assert(false); }

static void run_request(bool boot) {
    request_sent = false;
    replies = 0;
    if (setjmp(request_boundary) == 0) {
        if (boot) (void)blue_wallet_device_main();
        else answer_command();
        assert(false);
    }
    active_try = NULL;
    assert(request_sent && replies == 1 && response_length >= 2);
}

static size_t exchange(const uint8_t *apdu, size_t length,
    uint8_t *reply, bool boot) {
    assert(apdu && length <= sizeof request);
    memcpy(request, apdu, length);
    request_length = length;
    response_length = 0;
    run_request(boot);
    if (reply) memcpy(reply, response, response_length);
    return response_length;
}

static void expect_success(const uint8_t *apdu, size_t length, bool boot) {
    size_t received = exchange(apdu, length, NULL, boot);
    assert(response[received - 2] == 0x90 && response[received - 1] == 0);
}

static void start_payment(void) {
    static const uint8_t begin[] = {
        0xa5, 0x20, 0, 0, 12, 136, 0, 0, 0, 0, 0, 0, 0,
        0xbb, 0x09, 0xb8, 0x76
    };
    shown = NULL;
    shown_count = 0;
    expect_success(begin, sizeof begin, true);
    for (size_t i = 2; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(wallet_payment_visible() && shown == waiting_ui &&
        find_text("SEND NEXT CHUNK") && find_text("EXIT"));
}

static void test_reset_during_first_payment_command(void) {
    static const uint8_t begin[] = {
        0xa5, 0x20, 0, 0, 12, 136, 0, 0, 0, 0, 0, 0, 0,
        0xbb, 0x09, 0xb8, 0x76
    };
    assert(wallet_payment_account_ready() && !wallet_payment_visible());
    reset_during_blake_init = true;
    unsigned before = sign_calls;
    size_t length = exchange(begin, sizeof begin, NULL, false);
    assert(!reset_during_blake_init);
    assert(length == 2 && response[0] == 0x69 && response[1] == 0x85);
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(memcmp(&payment, &erased, sizeof payment) == 0 &&
        !wallet_payment_visible() && !blue_wallet_test_tick_ms &&
        sign_calls == before);
}

static bool device_exchange(void *context, const uint8_t *apdu,
    size_t length, uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    (void)context;
    assert(reply && reply_length);
    uint8_t received[260];
    size_t count = exchange(apdu, length, received, false);
    if (count > capacity) return false;
    memcpy(reply, received, count);
    *reply_length = count;
    return true;
}

static bool device_continue(void *context, uint32_t index,
    const blue_payment_screen *screen) {
    unsigned *continued = context;
    static const char other_address[] =
        "t3Mg6o2UpMFVtrzqGs7f2VTS6DaiPnFT5rL";
    const char *expected_address = index ? other_address : receive_address;
    const char *expected_amount = index ? "2.00000000 ZCL" :
        "1.00000000 ZCL";
    const char *expected_kind = index ? "P2SH ADDRESS" : "THIS ACCOUNT";
    assert(index == *continued && screen && shown == output_ui);
    assert(strcmp(payment.screen.title, screen->title) == 0);
    assert(strcmp(payment.screen.amount, screen->amount) == 0);
    assert(strcmp(payment.screen.amount, expected_amount) == 0 &&
        strcmp(payment.screen.kind, expected_kind) == 0 &&
        strcmp(payment.screen.address, expected_address) == 0 &&
        strcmp(screen->address, expected_address) == 0);
    char displayed_address[40] = {0};
    size_t displayed_used = 0;
    for (unsigned line = 0; line < 3; ++line)
        displayed_used = append_address_line(displayed_address,
            sizeof displayed_address, displayed_used,
            payment.screen.address_lines[line],
            sizeof payment.screen.address_lines[line]);
    assert(strcmp(displayed_address, expected_address) == 0);
    assert(find_text("ZCL MAINNET ADDRESS") && find_text("EXIT"));
    if (index == 1) {
        size_t address_length = strlen(payment.screen.address);
        size_t amount_length = strlen(payment.screen.amount);
        assert(address_length < sizeof observed_recipient &&
               amount_length < sizeof observed_amount);
        memcpy(observed_recipient, payment.screen.address,
               address_length + 1);
        memcpy(observed_amount, payment.screen.amount, amount_length + 1);
    }
    tap_text("CONTINUE");
    assert(shown == waiting_ui && !payment.review.pending);
    ++*continued;
    return true;
}

static void run_fixture_review(uint8_t digest[32]) {
    uint8_t owned[20];
    memcpy(owned, account_hash160, sizeof owned);
    blue_payment_fixture fixture;
    assert(blue_payment_fixture_make(owned, &fixture));
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(fixture.unsigned_wire,
        fixture.unsigned_length, BLUE_PAYMENT_FIXTURE_BRANCH, &plan));
    zcl_tx_previous_transaction previous = {
        .wire = fixture.previous, .length = fixture.previous_length};
    struct blake2b_ctx blake;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&blake);
    zcl_tx_transparent_facts facts;
    uint8_t digests[ZCL_TX_PREFLIGHT_MAX_INPUTS][32];
    assert(zcl_tx_transparent_bound_digests(fixture.unsigned_wire,
        fixture.unsigned_length, &previous, 1,
        BLUE_PAYMENT_FIXTURE_BRANCH, hash_sha256, &hasher,
        &facts, digests, ZCL_TX_PREFLIGHT_MAX_INPUTS) == 0);
    assert(facts.fee_zat == 100000000 && facts.transparent_outputs == 2);
    assert(memcmp(digests[0], fixture_digest, sizeof fixture_digest) == 0);
    unsigned continued = 0;
    assert(blue_payment_live_run_bound(fixture.unsigned_wire,
        fixture.unsigned_length, &plan, &previous, 1, facts.fee_zat,
        (const uint8_t (*)[32])digests, device_exchange,
        device_continue, &continued));
    assert(continued == 2 && shown == fee_ui &&
        payment.review.verified && payment.fee_ready);
    memcpy(digest, digests[0], 32);
}

static void check_final_review(const uint8_t digest[32]) {
    assert(find_text("1.00000000 ZCL") &&
        find_text("CHAIN UNCHECKED") && find_text("BRANCH UNCHECKED"));
    tap_text("TOTALS");
    assert(shown == totals_ui && find_text("2.00000000 ZCL") &&
        strcmp(others_text, "2.00000000 ZCL") == 0 &&
        strcmp(own_text, "1.00000000 ZCL") == 0 &&
        strcmp(fee_text, "1.00000000 ZCL") == 0);
    tap_text("NEXT");
    assert(shown == sign_ui && find_text("BRANCH 0x76B809BB") &&
        find_text("LOCK TIME 100") && find_text("EXPIRY 200") &&
        find_text("2.00000000 ZCL") && find_text("SIGN ZCL") &&
        find_text("NO SIGN"));
    assert(memcmp(payment.input_record[0], digest, 32) == 0);
}

static void check_fixture_signature_reply(const uint8_t reply[260],
    size_t length, uint8_t input_index) {
    static const uint8_t test_der[8] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
    };
    assert(length == 46 && reply[44] == 0x90 && reply[45] == 0 &&
        reply[0] == input_index && reply[1] == BLUE_PAYMENT_INPUT_EXTERNAL &&
        reply[2] == 2 && reply[35] == sizeof test_der &&
        memcmp(reply + 36, test_der, sizeof test_der) == 0);
    for (unsigned i = 3; i < 35; ++i) assert(reply[i] == 0x11);
}

static void make_two_input_fixture(blue_payment_fixture *fixture,
    uint8_t second_previous[BLUE_PAYMENT_FIXTURE_MAX_WIRE]) {
    enum { input_end = 50, input_length = 41, previous_value = 47 };
    assert(fixture->previous_length >= previous_value + 8 &&
        fixture->unsigned_length >= input_end &&
        fixture->unsigned_wire[8] == 1);
    assert(fixture->unsigned_length + input_length <=
        sizeof fixture->unsigned_wire);
    memcpy(second_previous, fixture->previous, fixture->previous_length);
    second_previous[42] = 0xfe;
    uint64_t value = 100000000;
    for (unsigned i = 0; i < 8; ++i)
        second_previous[previous_value + i] = (uint8_t)(value >> (8 * i));
    uint8_t first[32], txid[32];
    zsha256(second_previous, fixture->previous_length, first);
    zsha256(first, sizeof first, txid);
    memmove(fixture->unsigned_wire + input_end + input_length,
        fixture->unsigned_wire + input_end,
        fixture->unsigned_length - input_end);
    uint8_t *input = fixture->unsigned_wire + input_end;
    memcpy(input, txid, sizeof txid);
    memset(input + 32, 0, 5);
    input[37] = 0xfd;
    memset(input + 38, 0xff, 3);
    fixture->unsigned_wire[8] = 2;
    fixture->unsigned_length += input_length;
}

static void run_two_input_review(uint8_t digests[2][32]) {
    blue_payment_fixture fixture;
    assert(blue_payment_fixture_make(account_hash160, &fixture));
    uint8_t second_previous[BLUE_PAYMENT_FIXTURE_MAX_WIRE];
    make_two_input_fixture(&fixture, second_previous);
    blue_payment_live_plan plan;
    assert(blue_payment_live_prepare(fixture.unsigned_wire,
        fixture.unsigned_length, BLUE_PAYMENT_FIXTURE_BRANCH, &plan));
    assert(plan.inputs == 2 && plan.count == 2);
    zcl_tx_previous_transaction previous[2] = {
        {.wire = fixture.previous, .length = fixture.previous_length},
        {.wire = second_previous, .length = fixture.previous_length}
    };
    struct blake2b_ctx blake;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&blake);
    zcl_tx_transparent_facts facts;
    assert(zcl_tx_transparent_bound_digests(fixture.unsigned_wire,
        fixture.unsigned_length, previous, 2,
        BLUE_PAYMENT_FIXTURE_BRANCH, hash_sha256, &hasher,
        &facts, digests, 2) == 0);
    assert(facts.fee_zat == 200000000 &&
        memcmp(digests[0], digests[1], 32) != 0);
    unsigned continued = 0;
    assert(blue_payment_live_run_bound(fixture.unsigned_wire,
        fixture.unsigned_length, &plan, previous, 2, facts.fee_zat,
        (const uint8_t (*)[32])digests, device_exchange,
        device_continue, &continued));
    assert(continued == 2 && shown == fee_ui &&
        payment.review.verified && payment.fee_ready);
    tap_text("TOTALS");
    assert(shown == totals_ui &&
        strcmp(fee_text, "2.00000000 ZCL") == 0);
    tap_text("NEXT");
    assert(shown == sign_ui && find_text("SIGN ZCL") &&
        payment.input_count == 2 &&
        memcmp(payment.input_record[0], digests[0], 32) == 0 &&
        memcmp(payment.input_record[1], digests[1], 32) == 0);
}

static void test_two_input_signing_boundary(void) {
    uint8_t digests[2][32];
    run_two_input_review(digests);
    unsigned before = sign_calls;
    tap_text("SIGN ZCL");
    assert(shown == signing_ui && payment.approved);
    static const uint8_t first[] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t second[] = {0xa5, 0x29, 0, 0, 1, 1};
    uint8_t reply[260];
    size_t length = exchange(first, sizeof first, reply, false);
    check_fixture_signature_reply(reply, length, 0);
    assert(sign_calls == before + 1 &&
        memcmp(signed_digest, digests[0], 32) == 0 &&
        shown == signing_ui && payment.approved &&
        payment.next_sign_index == 1);
    length = exchange(second, sizeof second, reply, false);
    check_fixture_signature_reply(reply, length, 1);
    blue_payment_apdu erased;
    memset(&erased, 0, sizeof erased);
    erased.review.replay.wire.failed = true;
    assert(sign_calls == before + 2 &&
        memcmp(signed_digest, digests[1], 32) == 0 &&
        shown == signed_ui && sign_complete_view &&
        !payment.approved && !blue_wallet_test_tick_ms &&
        memcmp(&payment, &erased, sizeof payment) == 0);
    tap_exit();
}

static void test_two_input_wrong_first_index(void) {
    uint8_t digests[2][32];
    run_two_input_review(digests);
    unsigned before = sign_calls;
    tap_text("SIGN ZCL");
    static const uint8_t wrong[] = {0xa5, 0x29, 0, 0, 1, 1};
    size_t length = exchange(wrong, sizeof wrong, NULL, false);
    blue_payment_apdu erased;
    memset(&erased, 0, sizeof erased);
    erased.review.replay.wire.failed = true;
    assert(length == 2 && response[0] == 0x69 && response[1] == 0x85 &&
        sign_calls == before && shown == receive_ui &&
        !payment.approved && !blue_wallet_test_tick_ms &&
        memcmp(&payment, &erased, sizeof payment) == 0);
}

static void test_two_input_malformed_second(void) {
    uint8_t digests[2][32];
    run_two_input_review(digests);
    tap_text("SIGN ZCL");
    static const uint8_t first[] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t malformed[] = {0xa5, 0x29, 1, 0, 1, 1};
    static const uint8_t second[] = {0xa5, 0x29, 0, 0, 1, 1};
    uint8_t reply[260];
    size_t length = exchange(first, sizeof first, reply, false);
    check_fixture_signature_reply(reply, length, 0);
    unsigned before = sign_calls;
    assert(memcmp(signed_digest, digests[0], 32) == 0 &&
        payment.approved && payment.next_sign_index == 1);
    length = exchange(malformed, sizeof malformed, NULL, false);
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(length == 2 && response[0] == 0x6b && response[1] == 0 &&
        sign_calls == before && shown == receive_ui &&
        !wallet_payment_visible() && !blue_wallet_test_tick_ms &&
        memcmp(&payment, &erased, sizeof payment) == 0);
    for (size_t byte = 2; byte < sizeof G_io_apdu_buffer; ++byte)
        assert(G_io_apdu_buffer[byte] == 0);
    length = exchange(second, sizeof second, NULL, false);
    assert(length == 2 && response[0] == 0x69 &&
        response[1] == 0x85 && sign_calls == before);
}

static void test_cross_button_sign_touch(void) {
    uint8_t digest[32];
    run_fixture_review(digest);
    check_final_review(digest);
    const bagl_element_t *decline = find_text("NO SIGN");
    const bagl_element_t *approve = find_text("SIGN ZCL");
    assert(decline && approve);
    unsigned before = sign_calls;
    finger_event((unsigned)decline->component.x + 40,
        (unsigned)decline->component.y + 25,
        SEPROXYHAL_TAG_FINGER_EVENT_TOUCH);
    finger_release((unsigned)approve->component.x + 40,
        (unsigned)approve->component.y + 25);
    assert(shown == sign_ui && !payment.approved &&
        sign_calls == before);
    finger_event((unsigned)decline->component.x + 40,
        (unsigned)decline->component.y + 25,
        SEPROXYHAL_TAG_FINGER_EVENT_TOUCH);
    finger_event((unsigned)approve->component.x + 40,
        (unsigned)approve->component.y + 25,
        SEPROXYHAL_TAG_FINGER_EVENT_TOUCH);
    finger_release((unsigned)approve->component.x + 40,
        (unsigned)approve->component.y + 25);
    assert(shown == sign_ui && !payment.approved &&
        sign_calls == before);
    finger_release((unsigned)approve->component.x + 40,
        (unsigned)approve->component.y + 25);
    assert(shown == sign_ui && !payment.approved &&
        sign_calls == before);
    finger_event((unsigned)approve->component.x + 40,
        (unsigned)approve->component.y + 25,
        SEPROXYHAL_TAG_FINGER_EVENT_TOUCH);
    displayed_view = 0;
    wallet_payment_display();
    assert(shown == sign_ui);
    finger_release((unsigned)approve->component.x + 40,
        (unsigned)approve->component.y + 25);
    assert(shown == sign_ui && !payment.approved &&
        sign_calls == before);
    tap_text("NO SIGN");
    assert(shown == confirmed_ui);
}

static void test_two_input_interrupted_after_first(unsigned usb_event) {
    uint8_t digests[2][32];
    run_two_input_review(digests);
    unsigned before = sign_calls;
    tap_text("SIGN ZCL");
    static const uint8_t first[] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t second[] = {0xa5, 0x29, 0, 0, 1, 1};
    uint8_t reply[260];
    size_t length = exchange(first, sizeof first, reply, false);
    check_fixture_signature_reply(reply, length, 0);
    assert(sign_calls == before + 1 &&
        memcmp(signed_digest, digests[0], 32) == 0 &&
        payment.approved && payment.next_sign_index == 1 &&
        blue_wallet_test_tick_ms == 30000);
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    G_io_seproxyhal_spi_buffer[0] = usb_event ? SEPROXYHAL_TAG_USB_EVENT :
        SEPROXYHAL_TAG_TICKER_EVENT;
    G_io_seproxyhal_spi_buffer[3] = (uint8_t)usb_event;
    (void)io_event(CHANNEL_SPI);
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    blue_payment_apdu erased;
    memset(&erased, 0, sizeof erased);
    erased.review.replay.wire.failed = true;
    assert(shown == receive_ui && !wallet_payment_visible() &&
        !blue_wallet_test_tick_ms &&
        memcmp(&payment, &erased, sizeof payment) == 0);
    length = exchange(second, sizeof second, NULL, false);
    assert(length == 2 && response[0] == 0x69 && response[1] == 0x85 &&
        sign_calls == before + 1 && !payment.approved);
}

static void check_signing_denied(void);

static void test_fixture_signing_boundary(void) {
    uint8_t expected_digest[32];
    run_fixture_review(expected_digest);
    check_final_review(expected_digest);
    unsigned before = sign_calls;
    tap_text("SIGN ZCL");
    assert(shown == signing_ui && payment.approved);
    static const uint8_t sign[] = {0xa5, 0x29, 0, 0, 1, 0};
    uint8_t reply[260];
    size_t length = exchange(sign, sizeof sign, reply, false);
    check_fixture_signature_reply(reply, length, 0);
    assert(sign_calls == before + 1 &&
        signed_path == BLUE_PAYMENT_INPUT_EXTERNAL &&
        memcmp(signed_digest, expected_digest, 32) == 0);
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(shown == signed_ui && sign_complete_view &&
        !payment.approved && !blue_wallet_test_tick_ms &&
        memcmp(&payment, &erased, sizeof payment) == 0);
    tap_exit();
}

static void test_interrupt_inside_signer(unsigned interrupt) {
    uint8_t digest[32];
    run_fixture_review(digest);
    check_final_review(digest);
    tap_text("SIGN ZCL");
    unsigned before = sign_calls;
    static const uint8_t sign[] = {0xa5, 0x29, 0, 0, 1, 0};
    signer_interrupt = interrupt;
    size_t length = exchange(sign, sizeof sign, NULL, false);
    assert(!signer_interrupt && sign_calls == before + 1 &&
        length == 2 && response[0] == 0x69 && response[1] == 0x85);
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(memcmp(&payment, &erased, sizeof payment) == 0 &&
        !wallet_payment_visible() && !blue_wallet_test_tick_ms);
    check_signing_denied();
}

static void test_final_sign_material_mutation(void) {
    for (unsigned changed = 0; changed < 2; ++changed) {
        uint8_t digest[32];
        run_fixture_review(digest);
        check_final_review(digest);
        unsigned before = sign_calls;
        if (changed == 0) payment.input_record[0][0] ^= 1u;
        else payment.review.replay.commitment[0] ^= 1u;
        tap_text("SIGN ZCL");
        blue_payment_apdu erased = {0};
        erased.review.replay.wire.failed = true;
        assert(shown == ended_ui && !wallet_payment_visible() &&
            !payment.approved && sign_calls == before &&
            memcmp(&payment, &erased, sizeof payment) == 0);
        check_signing_denied();
    }
}

static void test_fixture_wrong_sign_index(void) {
    uint8_t expected_digest[32];
    run_fixture_review(expected_digest);
    check_final_review(expected_digest);
    unsigned before = sign_calls;
    tap_text("SIGN ZCL");
    static const uint8_t wrong_index[] = {0xa5, 0x29, 0, 0, 1, 1};
    size_t length = exchange(wrong_index, sizeof wrong_index, NULL, false);
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(length == 2 && response[0] == 0x69 && response[1] == 0x85 &&
        sign_calls == before && !wallet_payment_visible() &&
        shown == receive_ui && !blue_wallet_test_tick_ms &&
        memcmp(&payment, &erased, sizeof payment) == 0);
}

static void test_malformed_sign_after_approval(void) {
    static const struct {
        uint8_t request[7];
        size_t length;
        uint16_t status;
    } cases[] = {
        {{0xb5, 0x29, 0, 0, 1, 0}, 6, 0x6e00},
        {{0xa5, 0x29, 1, 0, 1, 0}, 6, 0x6b00},
        {{0xa5, 0x29, 0, 0, 1, 0}, 5, 0x6700},
        {{0xa5, 0x29, 0, 0, 1, 0, 0}, 7, 0x6700},
        {{0xa5, 0x2a, 0, 0, 1, 0}, 6, 0x6d00}
    };
    static const uint8_t valid[] = {0xa5, 0x29, 0, 0, 1, 0};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        uint8_t digest[32];
        run_fixture_review(digest);
        check_final_review(digest);
        tap_text("SIGN ZCL");
        assert(shown == signing_ui && payment.approved);
        unsigned before = sign_calls;
        size_t length = exchange(cases[i].request,
            cases[i].length, NULL, false);
        assert(length == 2 && response[0] == cases[i].status >> 8 &&
            response[1] == (cases[i].status & 255u));
        for (size_t byte = 2; byte < sizeof G_io_apdu_buffer; ++byte)
            assert(G_io_apdu_buffer[byte] == 0);
        blue_payment_apdu erased = {0};
        erased.review.replay.wire.failed = true;
        assert(sign_calls == before && shown == receive_ui &&
            !wallet_payment_visible() && !blue_wallet_test_tick_ms &&
            memcmp(&payment, &erased, sizeof payment) == 0);
        length = exchange(valid, sizeof valid, NULL, false);
        assert(length == 2 && response[0] == 0x69 &&
            response[1] == 0x85 && sign_calls == before);
    }
}

static void reset_approved_review(void) {
    tap_text("SIGN ZCL");
    assert(shown == signing_ui && payment.approved &&
        blue_wallet_test_tick_ms == 30000);
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
    G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_RESET;
    (void)io_event(CHANNEL_SPI);
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(shown == receive_ui && !wallet_payment_visible() &&
        !payment.approved && blue_wallet_test_tick_ms == 0);
}

static void check_signing_denied(void) {
    static const uint8_t sign[] = {0xa5, 0x29, 0, 0, 1, 0};
    size_t length = exchange(sign, sizeof sign, NULL, false);
    assert(length == 2 && response[0] == 0x69 && response[1] == 0x85);
    assert(!wallet_payment_visible() && !payment.approved);
    assert(shown == receive_ui && find_text("MATCH ALL 35 CHARACTERS"));
}

static void test_full_review(bool reset_after_approval) {
    uint8_t digest[32];
    run_fixture_review(digest);
    check_final_review(digest);
    if (reset_after_approval) reset_approved_review();
    else {
        tap_text("NO SIGN");
        blue_payment_apdu erased = {0};
        erased.review.replay.wire.failed = true;
        assert(shown == confirmed_ui && !payment.review_confirmed &&
            !payment.approved &&
            memcmp(&payment, &erased, sizeof payment) == 0);
    }
    check_signing_denied();
}

static void test_host_abort_after_approval(void) {
    uint8_t digest[32];
    run_fixture_review(digest);
    check_final_review(digest);
    tap_text("SIGN ZCL");
    assert(shown == signing_ui && payment.approved &&
        blue_wallet_test_tick_ms == 30000);
    assert(blue_payment_live_abort(device_exchange, NULL));
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(shown == ended_ui && blue_wallet_test_tick_ms == 0 &&
        memcmp(&payment, &erased, sizeof payment) == 0);
    check_signing_denied();
}

static void test_lock_during_sign_touch(void) {
    uint8_t digest[32];
    run_fixture_review(digest);
    check_final_review(digest);
    pin_valid = false;
    tap_text("SIGN ZCL");
    assert(shown == locked_ui && !wallet_payment_account_ready() &&
           !payment.approved && !wallet_payment_visible());
    pin_valid = true;
    static const uint8_t address[] = {0xa5, 0x02, 0, 0, 0};
    size_t length = exchange(address, sizeof address, NULL, false);
    assert(length == 2 && response[0] == 0x69 && response[1] == 0x85);
    tap_exit();
}

static void boot_identity(uint8_t reply[16], size_t *reply_length) {
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    *reply_length = exchange(identity, sizeof identity, reply, true);
}

static void assert_payment_erased(void) {
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(memcmp(&payment, &erased, sizeof payment) == 0);
    assert(!wallet_payment_visible() && !payment.approved);
}

static void refuse_release(const blue_host_gui_facts *gui,
                           const blue_host_gui_facts *screen,
                           const uint8_t *digest, int authority) {
    uint8_t out[16], sentinel[8];
    size_t out_length = 9;
    memset(out, 0x11, sizeof out);
    memset(sentinel, 0xa5, sizeof sentinel);
    assert(!blue_host_gui_release_signature(gui, screen, digest, 32,
        authority, sentinel, sizeof sentinel, out, sizeof out,
        &out_length));
    assert(out_length == 0);
    for (size_t i = 0; i < sizeof out; ++i) assert(out[i] == 0);
}

static void test_gui_matches_blue(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    assert(reply_length == 7 && reply[0] == 'Z' && reply[1] == 'C' &&
           reply[2] == 'L' && reply[5] == 0x90 && reply[6] == 0x00);
    assert(shown == receive_ui && find_text("RECEIVE ZCL"));
    blue_host_gui_facts loaded;
    assert(blue_host_gui_load_representative(&loaded));
    char version[16];
    assert(snprintf(version, sizeof version, "%u", reply[3]) > 0);
    assert(strcmp(version, loaded.app_version) == 0);
    assert(strcmp(loaded.app_name, "ZCL Wallet") == 0);
    assert(strcmp(loaded.app_version, "0.3.46") != 0);
    assert(strcmp(receive_address, loaded.receive) == 0);
    char joined[40] = {0};
    size_t joined_used = 0;
    for (unsigned line = 0; line < 3; ++line) {
        assert(find_text(address_lines[line]));
        joined_used = append_address_line(joined, sizeof joined, joined_used,
            address_lines[line], sizeof address_lines[line]);
    }
    assert(strcmp(joined, loaded.receive) == 0);
    unsigned before = sign_calls;
    uint8_t digest[32];
    run_fixture_review(digest);
    assert(memcmp(digest, loaded.digest, sizeof digest) == 0);
    assert(strcmp(observed_recipient, loaded.recipient) == 0);
    assert(strcmp(observed_amount, loaded.amount) == 0);
    assert(find_text(loaded.fee) && strcmp(fee_text, loaded.fee) == 0);
    check_final_review(digest);
    assert(find_text(loaded.network) && find_text(loaded.approval));
    assert(find_text("NO MEMO") == NULL && find_text("MEMO") == NULL);
    assert(memcmp(payment.input_record[0], loaded.digest, 32) == 0);
    blue_host_gui_facts screen;
    assert(blue_host_gui_facts_set(&screen, "Blue linked", "ZCL Wallet",
        version, receive_address, observed_recipient, observed_amount,
        fee_text, payment.screen.title, "NO MEMO", "SIGN ZCL",
        payment.input_record[0]));
    assert(strcmp(screen.network, loaded.network) == 0);
    assert(blue_host_gui_bind(&loaded, &screen, payment.input_record[0],
                              32) == BLUE_HOST_GUI_BIND_MATCH);
    struct {
        size_t offset;
        blue_host_gui_bind_status status;
    } fields[] = {
        {offsetof(blue_host_gui_facts, amount), BLUE_HOST_GUI_BIND_AMOUNT},
        {offsetof(blue_host_gui_facts, recipient),
         BLUE_HOST_GUI_BIND_RECIPIENT},
        {offsetof(blue_host_gui_facts, fee), BLUE_HOST_GUI_BIND_FEE},
        {offsetof(blue_host_gui_facts, network), BLUE_HOST_GUI_BIND_NETWORK},
        {offsetof(blue_host_gui_facts, memo), BLUE_HOST_GUI_BIND_MEMO}
    };
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; ++i) {
        blue_host_gui_facts changed = screen;
        char *field = (char *)&changed + fields[i].offset;
        field[0] = field[0] == 'A' ? 'B' : 'A';
        assert(blue_host_gui_bind(&loaded, &changed,
                                  payment.input_record[0], 32) ==
               fields[i].status);
        refuse_release(&loaded, &changed, payment.input_record[0],
                       BLUE_HOST_GUI_AUTHORITY_SIGN);
    }
    uint8_t wrong[32];
    memcpy(wrong, payment.input_record[0], sizeof wrong);
    wrong[0] ^= 0xff;
    assert(blue_host_gui_bind(&loaded, &screen, wrong, sizeof wrong) ==
           BLUE_HOST_GUI_BIND_DIGEST);
    refuse_release(&loaded, &screen, wrong, BLUE_HOST_GUI_AUTHORITY_SIGN);
    refuse_release(&loaded, &screen, payment.input_record[0],
                   BLUE_HOST_GUI_AUTHORITY_REVIEW);
    refuse_release(&loaded, &screen, payment.input_record[0],
                   BLUE_HOST_GUI_AUTHORITY_KEYS);
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_REVIEW,
                                        "ZCL Probe", "0.1.0"));
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_KEYS,
                                        "ZCL Wallet", "0.3.46"));
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_INSTALL,
                                        "ZCL Wallet", "0.3.46"));
    assert(!blue_install_image_allowed("ZCL Wallet", "0.3.46"));
    assert(sign_calls == before);
    tap_text("NO SIGN");
    assert(shown == confirmed_ui && find_text("NO SIGNING") &&
           !payment.approved);
    check_signing_denied();
    assert(sign_calls == before);
}

static void test_install_refusal(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    unsigned before = sign_calls;
    boot_identity(reply, &reply_length);
    assert(reply_length == 7 && !wallet_payment_visible());
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_INSTALL,
                                        "ZCL Wallet", "0.3.46"));
    assert(!blue_install_image_allowed("ZCL Wallet", "0.3.46"));
    assert(sign_calls == before && !payment.approved);
}

static void ticker_expire(void) {
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_TICKER_EVENT;
    G_io_seproxyhal_spi_buffer[3] = 0;
    (void)io_event(CHANNEL_SPI);
}

static void test_touch_approval_cannot_sign(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    blue_host_gui_facts loaded;
    assert(blue_host_gui_load_representative(&loaded));
    uint8_t digest[32];
    unsigned before = sign_calls;
    run_fixture_review(digest);
    check_final_review(digest);
    tap_text("SIGN ZCL");
    assert(shown == signing_ui && payment.approved &&
           blue_wallet_test_tick_ms == 30000 && sign_calls == before);
    blue_host_gui_facts changed = loaded;
    changed.amount[0] = changed.amount[0] == 'A' ? 'B' : 'A';
    refuse_release(&loaded, &changed, digest, BLUE_HOST_GUI_AUTHORITY_SIGN);
    refuse_release(&loaded, &loaded, digest, BLUE_HOST_GUI_AUTHORITY_REVIEW);
    assert(sign_calls == before && payment.approved);
    ticker_expire();
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(shown == receive_ui && !payment.approved &&
           blue_wallet_test_tick_ms == 0);
    assert_payment_erased();
    check_signing_denied();
    assert(sign_calls == before);
    assert(!blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_SIGN,
                                        "ZCL Wallet", "0.3.46"));
}

static void test_touch_rejection(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    blue_host_gui_facts loaded;
    assert(blue_host_gui_load_representative(&loaded));
    uint8_t digest[32];
    unsigned before = sign_calls;
    run_fixture_review(digest);
    check_final_review(digest);
    tap_text("NO SIGN");
    assert(shown == confirmed_ui && find_text("NO SIGNING") &&
           !payment.approved && sign_calls == before);
    blue_host_gui_facts rejected = loaded;
    assert(blue_host_gui_facts_set(&rejected, loaded.connection,
        loaded.app_name, loaded.app_version, loaded.receive,
        loaded.recipient, loaded.amount, loaded.fee, loaded.network,
        loaded.memo, "NO SIGNING", digest));
    assert(blue_host_gui_bind(&loaded, &rejected, digest, 32) ==
           BLUE_HOST_GUI_BIND_APPROVAL);
    refuse_release(&loaded, &rejected, digest, BLUE_HOST_GUI_AUTHORITY_SIGN);
    blue_payment_apdu erased = {0};
    erased.review.replay.wire.failed = true;
    assert(memcmp(&payment, &erased, sizeof payment) == 0);
    check_signing_denied();
    assert(sign_calls == before);
}

static void test_usb_loss(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    uint8_t digest[32];
    unsigned before = sign_calls;
    run_fixture_review(digest);
    check_final_review(digest);
    tap_text("SIGN ZCL");
    assert(payment.approved && sign_calls == before);
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
    G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_RESET;
    (void)io_event(CHANNEL_SPI);
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(shown == receive_ui);
    assert_payment_erased();
    check_signing_denied();
    assert(sign_calls == before);
}

static void test_cancel_on_fee(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    uint8_t digest[32];
    unsigned before_signs = sign_calls;
    unsigned before_exits = exits;
    run_fixture_review(digest);
    assert(shown == fee_ui && find_text("EXIT"));
    tap_text("EXIT");
    assert(exits == before_exits + 1 && receive_address[0] == 0 &&
           !wallet_payment_account_ready() && sign_calls == before_signs);
    blue_payment_apdu closed = {0};
    assert(memcmp(&payment, &closed, sizeof payment) == 0 &&
           !wallet_payment_visible() && !payment.approved);
    static const uint8_t sign[] = {0xa5, 0x29, 0, 0, 1, 0};
    size_t length = exchange(sign, sizeof sign, NULL, false);
    assert(length == 2 && response[0] == 0x69 && response[1] == 0x85 &&
           sign_calls == before_signs && !payment.approved);
}

static void test_approval_timeout(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    uint8_t digest[32];
    unsigned before = sign_calls;
    run_fixture_review(digest);
    check_final_review(digest);
    tap_text("SIGN ZCL");
    assert(shown == signing_ui && payment.approved &&
           blue_wallet_test_tick_ms == 30000);
    ticker_expire();
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(shown == receive_ui && blue_wallet_test_tick_ms == 0);
    assert_payment_erased();
    check_signing_denied();
    assert(sign_calls == before);
}

static void test_reboot_clears_approval(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    uint8_t digest[32];
    unsigned before = sign_calls;
    run_fixture_review(digest);
    check_final_review(digest);
    tap_text("SIGN ZCL");
    assert(payment.approved && shown == signing_ui);
    boot_identity(reply, &reply_length);
    assert(reply_length == 7 && reply[0] == 'Z' && !payment.approved &&
           !wallet_payment_visible() && shown == receive_ui &&
           sign_calls == before);
    check_signing_denied();
    assert(sign_calls == before);
}

static void test_hostile_apdu(void) {
    uint8_t reply[16];
    size_t reply_length = 0;
    boot_identity(reply, &reply_length);
    uint8_t digest[32];
    unsigned before = sign_calls;
    run_fixture_review(digest);
    assert(wallet_payment_visible() && shown == fee_ui);
    static const uint8_t hostile[] = {0x00, 0x21, 0, 0, 0};
    size_t length = exchange(hostile, sizeof hostile, NULL, false);
    assert(length == 2 && response[0] == 0x6e && response[1] == 0x00);
    assert(shown == receive_ui && sign_calls == before);
    assert_payment_erased();
    check_signing_denied();
    assert(sign_calls == before &&
           !blue_host_gui_permit_install(BLUE_HOST_GUI_AUTHORITY_REVIEW,
                                        "ZCL Wallet", "0.3.46"));
}

int main(void) {
    start_payment();
    unsigned before = exits;
    finger_release(0, 0);
    assert(exits == before && wallet_payment_visible());
    tap_exit();
    assert(exits == before + 1 && !wallet_payment_visible() &&
        !payment.active && signer_wipes >= 1);
    assert(!wallet_state.address_ready && !wallet_payment_account_ready() &&
           receive_address[0] == 0);
    start_payment();
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
    G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_USB_EVENT_RESET;
    (void)io_event(CHANNEL_SPI);
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(!wallet_payment_visible() && !payment.active &&
        shown == receive_ui && find_text("MATCH ALL 35 CHARACTERS"));
    before = exits;
    tap_exit();
    assert(exits == before + 1);
    assert(!wallet_payment_account_ready() && !wallet_state.address_ready);
    for (size_t i = 0; i < sizeof account_hash160; ++i)
        assert(account_hash160[i] == 0 && internal_hash160[i] == 0);
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    expect_success(identity, sizeof identity, true);
    test_reset_during_first_payment_command();
    test_full_review(false);
    test_full_review(true);
    test_host_abort_after_approval();
    test_lock_during_sign_touch();
    expect_success(identity, sizeof identity, true);
    test_fixture_wrong_sign_index();
    test_malformed_sign_after_approval();
    test_cross_button_sign_touch();
    test_final_sign_material_mutation();
    test_interrupt_inside_signer(1);
    test_interrupt_inside_signer(2);
    test_fixture_signing_boundary();
    expect_success(identity, sizeof identity, true);
    test_two_input_wrong_first_index();
    test_two_input_malformed_second();
    test_two_input_signing_boundary();
    expect_success(identity, sizeof identity, true);
    test_two_input_interrupted_after_first(SEPROXYHAL_TAG_USB_EVENT_RESET);
    test_two_input_interrupted_after_first(SEPROXYHAL_TAG_USB_EVENT_SUSPENDED);
    test_two_input_interrupted_after_first(0);
    test_gui_matches_blue();
    test_install_refusal();
    test_touch_approval_cannot_sign();
    test_touch_rejection();
    test_usb_loss();
    test_cancel_on_fee();
    test_approval_timeout();
    test_reboot_clears_approval();
    test_hostile_apdu();
    return 0;
}
