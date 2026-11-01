/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_address.h"
#include "zsha256/zsha256.h"
#include "zripemd/zripemd.h"

#undef NDEBUG
#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <string.h>

#define main blue_wallet_device_main
#include "../device-blue-wallet/src/main.c"
#undef main

unsigned char G_io_apdu_buffer[260];
unsigned blue_wallet_test_tick_ms;
static jmp_buf request_boundary;
static const bagl_element_t *shown;
static size_t shown_count;
static wallet_boot_material boot_material;
static uint8_t external_hash[20], internal_hash[20];
static unsigned derivations, displays, exits, aborts, signer_wipes;

/* Append one address line to out (holding `used` bytes), asserting that it fits. */
static size_t append_address_line(char *out, size_t out_size, size_t used,
    const char *line, size_t line_size) {
    size_t length = strnlen(line, line_size);
    assert(length < out_size - used);
    memcpy(out + used, line, length);
    out[used + length] = 0;
    return used + length;
}
static bool reject_second_path, reject_pin, reject_init,
    reject_init_status, reject_pair;
static bool pin_lost, drop_pin_on_internal_pair;
static bool drop_pin_on_internal_hash;
static bool throw_on_internal_pair;
static bool drop_pin_on_payment_request;
static bool drop_pin_on_receive;
static bool arm_pin_drop_after_receive, drop_pin_after_next_check;
static bool drop_pin_on_first_receive, restore_pin_on_second_receive;
static bool hashes_ready, payment_visible, timeout_pending;
typedef struct { const uint8_t *bytes; size_t length; } request_frame;
static const request_frame *requests;
static size_t request_count, request_next, reply_count;
static uint8_t replies[12][260];
static size_t reply_lengths[12];
static unsigned payment_commands;
static blue_try_context *active_try;
enum { IO_FAULT_NONE, IO_FAULT_RECEIVE, IO_FAULT_SEND };
static unsigned io_fault;
static size_t fault_after;
static bool fault_fired;
static bool reply_owed, accept_payment_begin, accept_payment_sign;
static bool overlong_payment_reply;
static unsigned short forged_receive_length;
static bool allow_payment_display;
static unsigned payment_displays;
static bool payment_approved;
static bool throw_after_payment_sign;
static unsigned usb_event_on_reply;
static size_t usb_event_reply_index;
static bool usb_event_fired, usb_event_before_reply;
static unsigned display_fault_at;
static bool display_fault_fired;

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
    ++displays;
    if (display_fault_at && displays == display_fault_at) {
        display_fault_fired = true;
        blue_throw(0x6813);
    }
}

wallet_boot_material *wallet_payment_boot_material(void) {
    return &boot_material;
}

void wallet_payment_boot_clear(void) {
    volatile uint8_t *bytes = (volatile uint8_t *)&boot_material;
    for (size_t i = 0; i < sizeof boot_material; ++i) bytes[i] = 0;
}

void wallet_payment_set_account_hashes(const uint8_t external[20],
    const uint8_t internal[20]) {
    memcpy(external_hash, external, sizeof external_hash);
    memcpy(internal_hash, internal, sizeof internal_hash);
    hashes_ready = true;
}

bool wallet_payment_account_ready(void) { return hashes_ready; }

void wallet_payment_revoke_account(void) {
    wallet_payment_abort();
    memset(external_hash, 0, sizeof external_hash);
    memset(internal_hash, 0, sizeof internal_hash);
    hashes_ready = false;
}

/* Boot counts one wipe. Scripted visibility stays so a later command
   can redraw. */
void wallet_payment_boot_reset(void) {
    ++aborts;
}

void wallet_payment_abort(void) {
    ++aborts;
    payment_visible = false;
    payment_approved = false;
}
bool wallet_payment_interrupt(void) {
    wallet_payment_abort();
    return true;
}
void wallet_payment_display(void) {
    assert(allow_payment_display);
    ++payment_displays;
}
bool wallet_payment_visible(void) { return payment_visible; }
bool wallet_payment_finger_allowed(const unsigned char *event) {
    return event != NULL;
}
bool wallet_payment_timeout(void) {
    if (!timeout_pending) return false;
    timeout_pending = false;
    wallet_payment_abort();
    return true;
}
uint16_t wallet_payment_command(const uint8_t *apdu, size_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    assert(apdu && length >= 2 && apdu[1] >= 0x20);
    ++payment_commands;
    *reply_length = 0;
    if (drop_pin_on_payment_request) {
        pin_lost = true;
        wallet_payment_abort();
        memset(reply, 0, capacity);
        return 0x6985;
    }
    if (accept_payment_begin && apdu[1] == 0x20) {
        payment_visible = true;
        return 0x9000;
    }
    if (overlong_payment_reply && apdu[1] == 0x20) {
        payment_visible = true;
        *reply_length = capacity + 1;
        return 0x9000;
    }
    if (accept_payment_sign && apdu[1] == 0x29 &&
        reply && capacity >= 8) {
        payment_approved = true;
        memset(reply, 0x5a, 8);
        *reply_length = 8;
        payment_visible = true;
        payment_approved = false;
        if (throw_after_payment_sign) blue_throw(0x6814);
        return 0x9000;
    }
    return 0x6985;
}
void blue_wallet_signer_wipe(void) { ++signer_wipes; }

int os_global_pin_is_validated(void) {
    if (drop_pin_after_next_check) {
        drop_pin_after_next_check = false;
        pin_lost = true;
        return 1;
    }
    return !reject_pin && !pin_lost &&
        (!reject_second_path || derivations == 0);
}

void os_perso_derive_node_bip32(unsigned curve, const unsigned *path,
    unsigned length, uint8_t raw[32], uint8_t chain[32]) {
    assert(curve == CX_CURVE_256K1 && length == 5);
    assert(path[0] == 0x8000002c && path[1] == 0x80000093);
    assert(path[2] == 0x80000000 && path[3] <= 1 && path[4] == 0);
    ++derivations;
    memset(raw, path[3] ? 0x22 : 0x11, 32);
    memset(chain, path[3] ? 0x44 : 0x33, 32);
}

int cx_ecfp_init_private_key(unsigned curve, const uint8_t raw[32],
    unsigned length, cx_ecfp_private_key_t *key) {
    assert(curve == CX_CURVE_256K1 && length == 32);
    key->curve = curve;
    key->d_len = length;
    memcpy(key->d, raw, length);
    if (reject_init) key->d_len = 0;
    return reject_init_status ? -1 : 0;
}

int cx_ecfp_generate_pair(unsigned curve, cx_ecfp_public_key_t *public_key,
    cx_ecfp_private_key_t *private_key, int keepprivate) {
    assert(curve == CX_CURVE_256K1 && keepprivate == 1);
    public_key->curve = curve;
    public_key->W_len = 65;
    public_key->W[0] = 4;
    memcpy(public_key->W + 1, private_key->d, 32);
    memset(public_key->W + 33, private_key->d[0] + 1, 32);
    if (throw_on_internal_pair && derivations == 2) blue_throw(0x6815);
    if (drop_pin_on_internal_pair && derivations == 2) pin_lost = true;
    return reject_pair ? -1 : 0;
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
    if (drop_pin_on_internal_hash && derivations == 2) pin_lost = true;
    return 20;
}

void os_boot(void) {}
void io_seproxyhal_init(void) {}
void USB_power(int enabled) { assert(enabled == 0 || enabled == 1); }
void os_sched_exit(unsigned code) { assert(code == 0); ++exits; }
static void maybe_usb_event(bool before_reply) {
    if (!usb_event_on_reply || usb_event_fired ||
        reply_count + (before_reply ? 1u : 0u) != usb_event_reply_index ||
        usb_event_before_reply != before_reply) return;
    usb_event_fired = true;
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
    G_io_seproxyhal_spi_buffer[3] = (uint8_t)usb_event_on_reply;
    (void)io_event(CHANNEL_SPI);
}

static void assert_cleared_reply_tail(size_t transmitted) {
    for (size_t i = transmitted; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
}

static unsigned short reported_receive_length(size_t copied) {
    return forged_receive_length ? forged_receive_length :
        (unsigned short)copied;
}

unsigned short io_exchange(unsigned char channel, unsigned short tx_length) {
    if (tx_length) {
        assert(channel == (CHANNEL_APDU | IO_RETURN_AFTER_TX));
        assert(reply_owed);
        if (io_fault == IO_FAULT_SEND && !fault_fired &&
            reply_count == fault_after) {
            fault_fired = true;
            blue_throw(0x6811);
        }
        assert(reply_count < sizeof replies / sizeof replies[0]);
        assert(tx_length <= sizeof replies[0]);
        maybe_usb_event(true);
        assert_cleared_reply_tail(tx_length);
        memcpy(replies[reply_count], G_io_apdu_buffer, tx_length);
        reply_lengths[reply_count++] = tx_length;
        maybe_usb_event(false);
        reply_owed = false;
        return 0;
    }
    assert(channel == CHANNEL_APDU);
    assert(!reply_owed);
    if (io_fault == IO_FAULT_RECEIVE && !fault_fired &&
        request_next == fault_after) {
        fault_fired = true;
        blue_throw(0x6812);
    }
    if (request_next == request_count) longjmp(request_boundary, 1);
    const request_frame *request = &requests[request_next++];
    assert(request->length <= sizeof G_io_apdu_buffer);
    memcpy(G_io_apdu_buffer, request->bytes, request->length);
    if (drop_pin_on_receive) pin_lost = true;
    if (arm_pin_drop_after_receive) drop_pin_after_next_check = true;
    if (drop_pin_on_first_receive && request_next == 1) pin_lost = true;
    if (restore_pin_on_second_receive && request_next == 2)
        pin_lost = false;
    reply_owed = true;
    return reported_receive_length(request->length);
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

static const bagl_element_t *find_text(const char *text) {
    for (size_t i = 0; i < shown_count; ++i)
        if (shown[i].text && strcmp(shown[i].text, text) == 0)
            return &shown[i];
    return NULL;
}

void blue_wallet_test_finger(const unsigned char *buffer) {
    assert(buffer[0] == SEPROXYHAL_TAG_FINGER_EVENT);
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

static void finger_release(unsigned x, unsigned y) {
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_FINGER_EVENT;
    G_io_seproxyhal_spi_buffer[3] = SEPROXYHAL_TAG_FINGER_EVENT_RELEASE;
    G_io_seproxyhal_spi_buffer[4] = (uint8_t)(x >> 8);
    G_io_seproxyhal_spi_buffer[5] = (uint8_t)x;
    G_io_seproxyhal_spi_buffer[6] = (uint8_t)(y >> 8);
    G_io_seproxyhal_spi_buffer[7] = (uint8_t)y;
    (void)io_event(CHANNEL_SPI);
}

static void check_exit_touch(void) {
    const bagl_element_t *exit_button = find_text("EXIT");
    assert(exit_button && exit_button->tap);
    unsigned before = exits;
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    finger_release(0, 0);
    assert(exits == before);
    finger_release((unsigned)exit_button->component.x +
                       (unsigned)exit_button->component.width / 2,
                   (unsigned)exit_button->component.y +
                       (unsigned)exit_button->component.height / 2);
    assert(exits == before + 1);
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(!wallet_state.address_ready && !hashes_ready &&
           receive_address[0] == 0);
    for (size_t i = 0; i < sizeof wallet_state.public_key; ++i)
        assert(wallet_state.public_key[i] == 0);
    for (size_t i = 0; i < sizeof address_lines; ++i)
        assert(((const uint8_t *)address_lines)[i] == 0);
}

static void reset_start(void) {
    shown = NULL;
    shown_count = 0;
    derivations = 0;
    pin_lost = false;
    drop_pin_after_next_check = false;
    request_next = 0;
    reply_count = 0;
    reply_owed = false;
    hashes_ready = false;
    memset(external_hash, 0, sizeof external_hash);
    memset(internal_hash, 0, sizeof internal_hash);
}

static void start_until_request(void) {
    reset_start();
    if (setjmp(request_boundary) == 0) {
        (void)blue_wallet_device_main();
        assert(false);
    }
    active_try = NULL;
    assert(shown && find_text("EXIT"));
}

static void start_until_exit(void) {
    reset_start();
    assert(blue_wallet_device_main() == 0);
    assert(!active_try && shown);
}

static void expect_status(size_t index, uint16_t status) {
    assert(index < reply_count && reply_lengths[index] >= 2);
    size_t tail = reply_lengths[index] - 2;
    assert(replies[index][tail] == (uint8_t)(status >> 8));
    assert(replies[index][tail + 1] == (uint8_t)status);
}

static void test_apdu_sequence(void) {
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    static const uint8_t address[] = {0xa5, 0x02, 0, 0, 0};
    static const uint8_t short_frame[] = {0xa5};
    static const uint8_t wrong_class[] = {0, 0x01, 0, 0, 0};
    static const uint8_t wrong_path[] = {0xa5, 0x02, 1, 0, 0};
    static const uint8_t unknown[] = {0xa5, 0x03, 0, 0, 0};
    static const uint8_t bad_length[] = {0xa5, 0x02, 0, 0, 1};
    static const uint8_t payment_begin[] = {0xa5, 0x20, 0, 0, 0};
    static const request_frame sequence[] = {
        {identity, sizeof identity}, {address, sizeof address},
        {short_frame, sizeof short_frame},
        {wrong_class, sizeof wrong_class},
        {wrong_path, sizeof wrong_path}, {unknown, sizeof unknown},
        {bad_length, sizeof bad_length},
        {payment_begin, sizeof payment_begin}
    };
    requests = sequence;
    request_count = sizeof sequence / sizeof sequence[0];
    payment_visible = true;
    unsigned before_aborts = aborts, before_displays = displays;
    start_until_request();
    assert(shown == receive_ui && request_next == request_count);
    assert(reply_count == request_count && !reply_owed);
    assert(payment_commands == 1);
    assert(aborts == before_aborts + 2 && displays == before_displays + 3);
    assert(reply_lengths[0] == 7 && blue_wallet_identity_matches(
        replies[0], reply_lengths[0]));
    assert(reply_lengths[1] == 35 && memcmp(replies[1],
        wallet_state.public_key, 33) == 0);
    for (size_t i = 0; i < reply_count; ++i)
        expect_status(i, i < 2 ? 0x9000 : i == 2 || i == 6 ? 0x6700 :
            i == 3 ? 0x6e00 : i == 4 ? 0x6b00 :
            i == 5 ? 0x6d00 : 0x6985);
    requests = NULL;
    request_count = 0;
}

static void test_overlong_payment_reply(void) {
    static const uint8_t begin[] = {0xa5, 0x20, 0, 0, 0};
    static const request_frame one[] = {{begin, sizeof begin}};
    requests = one;
    request_count = 1;
    overlong_payment_reply = true;
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    start_until_request();
    assert(reply_count == 1 && reply_lengths[0] == 2);
    expect_status(0, 0x6f00);
    assert(!payment_visible && shown == receive_ui && !reply_owed);
    for (size_t i = 2; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    overlong_payment_reply = false;
    requests = NULL;
    request_count = 0;
}

static void test_overlong_receive_count(void) {
    static const uint8_t begin[] = {0xa5, 0x20, 0, 0, 0};
    static const request_frame one[] = {{begin, sizeof begin}};
    requests = one;
    request_count = 1;
    accept_payment_begin = true;
    allow_payment_display = true;
    for (unsigned test = 0; test < 2; ++test) {
        forged_receive_length = test ? UINT16_MAX :
            (unsigned short)(sizeof G_io_apdu_buffer + 1);
        unsigned before_commands = payment_commands;
        unsigned before_aborts = aborts;
        memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
        start_until_request();
        assert(reply_count == 1 && reply_lengths[0] == 2);
        expect_status(0, 0x6700);
        assert(payment_commands == before_commands &&
               aborts > before_aborts && !payment_visible &&
               shown == receive_ui && !reply_owed);
        assert_cleared_reply_tail(2);
    }
    forged_receive_length = 0;
    accept_payment_begin = false;
    allow_payment_display = false;
    requests = NULL;
    request_count = 0;
}

static void test_unavailable_address_apdu(void) {
    static const uint8_t address[] = {0xa5, 0x02, 0, 0, 0};
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    static const request_frame sequence[] = {
        {address, sizeof address}, {identity, sizeof identity}
    };
    requests = sequence;
    request_count = sizeof sequence / sizeof sequence[0];
    reject_pin = true;
    start_until_request();
    assert(shown == locked_ui && !wallet_state.address_ready);
    assert(reply_count == request_count && !hashes_ready);
    assert(!reply_owed);
    expect_status(0, 0x6985);
    expect_status(1, 0x9000);
    assert(blue_wallet_identity_matches(replies[1], reply_lengths[1]));
    requests = NULL;
    request_count = 0;
}

static void test_lock_after_payment_request(void) {
    static const uint8_t begin[] = {0xa5, 0x20, 0, 0, 0};
    static const request_frame one[] = {{begin, sizeof begin}};
    requests = one;
    request_count = 1;
    payment_visible = true;
    drop_pin_on_payment_request = true;
    start_until_request();
    assert(derivations == 2 && wallet_state.address_ready && !hashes_ready);
    assert(reply_count == 1 && reply_lengths[0] == 2);
    expect_status(0, 0x6985);
    assert(!payment_visible && find_text("DEVICE LOCKED") &&
           !find_text("RECEIVE ZCL"));
    drop_pin_on_payment_request = false;
    check_exit_touch();
    requests = NULL;
    request_count = 0;
}

static void test_lock_before_address_request(void) {
    static const uint8_t address[] = {0xa5, 0x02, 0, 0, 0};
    static const request_frame one[] = {{address, sizeof address}};
    requests = one;
    request_count = 1;
    drop_pin_on_receive = true;
    start_until_request();
    assert(derivations == 2 && wallet_state.address_ready && !hashes_ready);
    assert(reply_count == 1 && reply_lengths[0] == 2);
    expect_status(0, 0x6985);
    assert(shown == locked_ui && !find_text("RECEIVE ZCL"));
    for (size_t i = 2; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    drop_pin_on_receive = false;
    check_exit_touch();
    requests = NULL;
    request_count = 0;
}

static void test_lock_during_address_request(void) {
    static const uint8_t address[] = {0xa5, 0x02, 0, 0, 0};
    static const request_frame one[] = {{address, sizeof address}};
    requests = one;
    request_count = 1;
    arm_pin_drop_after_receive = true;
    start_until_request();
    assert(derivations == 2 && wallet_state.address_ready && !hashes_ready);
    assert(reply_count == 1 && reply_lengths[0] == 2);
    expect_status(0, 0x6985);
    assert(shown == locked_ui);
    arm_pin_drop_after_receive = false;
    check_exit_touch();
    requests = NULL;
    request_count = 0;
}

static void test_lock_persists_after_pin_returns(void) {
    static const uint8_t address[] = {0xa5, 0x02, 0, 0, 0};
    static const uint8_t begin[] = {0xa5, 0x20, 0, 0, 0};
    static const request_frame sequence[] = {
        {address, sizeof address}, {address, sizeof address},
        {begin, sizeof begin}
    };
    requests = sequence;
    request_count = 3;
    drop_pin_on_first_receive = true;
    restore_pin_on_second_receive = true;
    start_until_request();
    assert(derivations == 2 && reply_count == 3);
    assert(reply_lengths[0] == 2 && reply_lengths[1] == 2 &&
           reply_lengths[2] == 2);
    expect_status(0, 0x6985);
    expect_status(1, 0x6985);
    expect_status(2, 0x6985);
    assert(!hashes_ready && shown == locked_ui);
    assert(receive_address[0] == 0);
    for (size_t i = 0; i < sizeof wallet_state.public_key; ++i)
        assert(wallet_state.public_key[i] == 0);
    for (size_t i = 0; i < sizeof address_lines; ++i)
        assert(((const uint8_t *)address_lines)[i] == 0);
    drop_pin_on_first_receive = false;
    restore_pin_on_second_receive = false;
    check_exit_touch();
    requests = NULL;
    request_count = 0;
}

static void test_lock_during_review_event(void) {
    requests = NULL;
    request_count = 0;
    start_until_request();
    for (unsigned event = SEPROXYHAL_TAG_USB_EVENT_RESET;
         event <= SEPROXYHAL_TAG_USB_EVENT_SUSPENDED; ++event) {
        pin_lost = true;
        payment_visible = true;
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
        G_io_seproxyhal_spi_buffer[3] = (uint8_t)event;
        (void)io_event(CHANNEL_SPI);
        assert(!payment_visible && shown == locked_ui);
        assert(find_text("DEVICE LOCKED") && !find_text("RECEIVE ZCL"));
    }
    payment_visible = true;
    timeout_pending = true;
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_TICKER_EVENT;
    (void)io_event(CHANNEL_SPI);
    assert(!payment_visible && !timeout_pending && shown == locked_ui);
    check_exit_touch();
}

static void test_idle_lock_on_tick(void) {
    requests = NULL;
    request_count = 0;
    start_until_request();
    assert(shown == receive_ui && hashes_ready);
    pin_lost = true;
    timeout_pending = false;
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_TICKER_EVENT;
    (void)io_event(CHANNEL_SPI);
    assert(shown == locked_ui && !hashes_ready);
    assert(receive_address[0] == 0 && wallet_state.public_key[0] == 0);
    check_exit_touch();
}

static void test_io_failures(void) {
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    static const request_frame one[] = {{identity, sizeof identity}};
    requests = NULL;
    request_count = 0;
    io_fault = IO_FAULT_RECEIVE;
    fault_after = 0;
    fault_fired = false;
    unsigned before = aborts;
    start_until_exit();
    assert(fault_fired && reply_count == 0 && aborts > before);
    assert(shown == receive_ui);
    assert(!wallet_state.address_ready && !hashes_ready &&
           receive_address[0] == 0);
    for (size_t i = 0; i < sizeof wallet_state.public_key; ++i)
        assert(wallet_state.public_key[i] == 0);

    requests = one;
    request_count = 1;
    io_fault = IO_FAULT_SEND;
    fault_fired = false;
    before = aborts;
    start_until_exit();
    assert(fault_fired && request_next == 1 && reply_count == 0);
    assert(aborts > before && shown == receive_ui);

    io_fault = IO_FAULT_RECEIVE;
    fault_after = 1;
    fault_fired = false;
    before = aborts;
    start_until_exit();
    assert(fault_fired && request_next == 1 && reply_count == 1);
    assert(blue_wallet_identity_matches(replies[0], reply_lengths[0]));
    assert(aborts > before && shown == receive_ui);
    io_fault = IO_FAULT_NONE;
    requests = NULL;
    request_count = 0;
}

static void test_sign_exception_cleanup(void) {
    static const uint8_t sign[] = {0xa5, 0x29, 0, 0, 1, 0};
    static const request_frame one[] = {{sign, sizeof sign}};
    requests = one;
    request_count = 1;
    accept_payment_sign = true;
    payment_visible = payment_approved = true;
    throw_after_payment_sign = true;
    start_until_request();
    assert(reply_count == 1 && reply_lengths[0] == 2);
    expect_status(0, 0x6814);
    for (size_t i = 2; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(!payment_visible && !payment_approved);
    throw_after_payment_sign = false;

    io_fault = IO_FAULT_SEND;
    fault_after = 0;
    fault_fired = false;
    payment_visible = payment_approved = true;
    start_until_exit();
    assert(fault_fired && request_next == 1 && reply_count == 0);
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(!payment_visible && !payment_approved);
    io_fault = IO_FAULT_NONE;
    accept_payment_sign = false;
    requests = NULL;
    request_count = 0;
}

static void test_post_reply_display_failure(void) {
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    static const request_frame one[] = {{identity, sizeof identity}};
    requests = one;
    request_count = 1;
    payment_visible = true;
    display_fault_at = displays + 2;
    display_fault_fired = false;
    unsigned before = aborts;
    start_until_exit();
    assert(display_fault_fired && request_next == 1 && reply_count == 1);
    assert(blue_wallet_identity_matches(replies[0], reply_lengths[0]));
    assert(aborts >= before + 2);
    display_fault_at = 0;
    requests = NULL;
    request_count = 0;
}

static void test_usb_reset_during_reply(void) {
    static const uint8_t begin[] = {0xa5, 0x20, 0, 0, 0};
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    static const request_frame sequence[] = {
        {begin, sizeof begin}, {identity, sizeof identity}
    };
    requests = sequence;
    request_count = sizeof sequence / sizeof sequence[0];
    accept_payment_begin = true;
    usb_event_reply_index = 1;
    for (unsigned event = SEPROXYHAL_TAG_USB_EVENT_RESET;
         event <= SEPROXYHAL_TAG_USB_EVENT_SUSPENDED; ++event) {
        usb_event_on_reply = event;
        usb_event_fired = false;
        unsigned before = aborts;
        start_until_request();
        assert(usb_event_fired && reply_count == 2 && !reply_owed);
        assert(!payment_visible && aborts == before + 2);
        assert(shown == receive_ui && blue_wallet_identity_matches(
            replies[1], reply_lengths[1]));
        expect_status(0, 0x9000);
    }
    usb_event_on_reply = 0;
    accept_payment_begin = false;
    requests = NULL;
    request_count = 0;
}

static void test_usb_reset_before_signature_reply(void) {
    static const uint8_t sign[] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    static const request_frame sequence[] = {
        {sign, sizeof sign}, {identity, sizeof identity}
    };
    requests = sequence;
    request_count = sizeof sequence / sizeof sequence[0];
    accept_payment_sign = true;
    usb_event_before_reply = true;
    usb_event_reply_index = 1;
    for (unsigned event = SEPROXYHAL_TAG_USB_EVENT_RESET;
         event <= SEPROXYHAL_TAG_USB_EVENT_SUSPENDED; ++event) {
        payment_visible = payment_approved = true;
        usb_event_on_reply = event;
        usb_event_fired = false;
        unsigned before = aborts;
        start_until_request();
        assert(usb_event_fired && reply_count == 2 && !reply_owed);
        assert(!payment_visible && !payment_approved && aborts == before + 2);
        assert(reply_lengths[0] == 10 && reply_lengths[1] == 7);
        for (size_t i = 0; i < reply_lengths[0]; ++i)
            assert(replies[0][i] == 0);
        assert(shown == receive_ui && blue_wallet_identity_matches(
            replies[1], reply_lengths[1]));
    }
    usb_event_on_reply = 0;
    usb_event_before_reply = false;
    accept_payment_sign = false;
    requests = NULL;
    request_count = 0;
}

static void test_signature_then_identity_reply(void) {
    static const uint8_t sign[] = {0xa5, 0x29, 0, 0, 1, 0};
    static const uint8_t identity[] = {0xa5, 0x01, 0, 0, 0};
    static const request_frame sequence[] = {
        {sign, sizeof sign}, {identity, sizeof identity}
    };
    requests = sequence;
    request_count = sizeof sequence / sizeof sequence[0];
    payment_visible = payment_approved = accept_payment_sign = true;
    allow_payment_display = true;
    unsigned before_displays = payment_displays;
    start_until_request();
    assert(reply_count == 2 && reply_lengths[0] == 10 &&
           reply_lengths[1] == 7 && !reply_owed);
    for (size_t i = 0; i < 8; ++i) assert(replies[0][i] == 0x5a);
    expect_status(0, 0x9000);
    assert(blue_wallet_identity_matches(replies[1], reply_lengths[1]) &&
           !payment_visible && !payment_approved &&
           payment_displays == before_displays + 1);
    for (size_t i = reply_lengths[1]; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    accept_payment_sign = false;
    allow_payment_display = false;
    requests = NULL;
    request_count = 0;
}

static void check_error_startup(unsigned expected_derivations) {
    start_until_request();
    assert(shown == (os_global_pin_is_validated() ? error_ui : locked_ui) &&
           !wallet_state.address_ready);
    assert(derivations == expected_derivations && !hashes_ready);
    assert(receive_address[0] == 0 && wallet_state.public_key[0] == 0);
    for (size_t i = 0; i < sizeof address_lines; ++i)
        assert(((const uint8_t *)address_lines)[i] == 0);
    for (size_t i = 0; i < sizeof boot_material; ++i)
        assert(((const uint8_t *)&boot_material)[i] == 0);
    check_exit_touch();
}

static void test_boot_exception_cleanup(void) {
    reset_start();
    throw_on_internal_pair = true;
    (void)blue_wallet_device_main();
    throw_on_internal_pair = false;
    assert(shown == NULL && derivations == 2 && !hashes_ready);
    for (size_t i = 0; i < sizeof boot_material; ++i)
        assert(((const uint8_t *)&boot_material)[i] == 0);
}

int main(void) {
    start_until_request();
    assert(aborts == 1 && shown == receive_ui && wallet_state.address_ready);
    assert(derivations == 2 && hashes_ready);
    assert(memcmp(external_hash, internal_hash, 20) != 0);
    char expected[ZCL_ADDRESS_SIZE];
    assert(zcl_address_from_hash160(external_hash, false, expected) == 0);
    assert(strcmp(receive_address, expected) == 0);
    char combined[ZCL_WALLET_ADDRESS_CHARS + 1] = {0};
    size_t combined_used = 0;
    for (size_t i = 0; i < ZCL_WALLET_ADDRESS_LINES; ++i)
        combined_used = append_address_line(combined, sizeof combined,
            combined_used, address_lines[i], sizeof address_lines[i]);
    assert(strcmp(combined, expected) == 0);
    for (unsigned event = SEPROXYHAL_TAG_USB_EVENT_RESET;
         event <= SEPROXYHAL_TAG_USB_EVENT_SUSPENDED; ++event) {
        payment_visible = true;
        unsigned before = aborts;
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EVENT;
        G_io_seproxyhal_spi_buffer[3] = (uint8_t)event;
        (void)io_event(CHANNEL_SPI);
        assert(!payment_visible && aborts == before + 1);
        assert(shown == receive_ui);
    }
    timeout_pending = true;
    unsigned before = aborts;
    memset(G_io_apdu_buffer, 0xa5, sizeof G_io_apdu_buffer);
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_TICKER_EVENT;
    (void)io_event(CHANNEL_SPI);
    for (size_t i = 0; i < sizeof G_io_apdu_buffer; ++i)
        assert(G_io_apdu_buffer[i] == 0);
    assert(!timeout_pending && aborts == before + 1);
    assert(shown == receive_ui);
    check_exit_touch();
    assert(exits == 1 && aborts == 5 && signer_wipes == 4);

    reject_second_path = true;
    check_error_startup(1);
    reject_second_path = false;
    reject_init = true;
    check_error_startup(1);
    reject_init = false;
    reject_pair = true;
    check_error_startup(1);
    reject_pair = false;
    drop_pin_on_internal_pair = true;
    check_error_startup(2);
    drop_pin_on_internal_pair = false;
    drop_pin_on_internal_hash = true;
    check_error_startup(2);
    drop_pin_on_internal_hash = false;
    reject_pin = true;
    check_error_startup(0);
    assert(displays == 10 && exits == 7);
    assert(aborts == 17 && signer_wipes == 10);
    reject_pin = false;
    reject_init_status = true;
    check_error_startup(1);
    reject_init_status = false;
    test_boot_exception_cleanup();
    test_apdu_sequence();
    test_overlong_payment_reply();
    test_overlong_receive_count();
    test_unavailable_address_apdu();
    reject_pin = false;
    test_lock_after_payment_request();
    test_lock_before_address_request();
    test_lock_during_address_request();
    test_lock_persists_after_pin_returns();
    test_lock_during_review_event();
    test_idle_lock_on_tick();
    test_io_failures();
    test_sign_exception_cleanup();
    test_post_reply_display_failure();
    test_usb_reset_during_reply();
    test_usb_reset_before_signature_reply();
    test_signature_then_identity_reply();
    return 0;
}
