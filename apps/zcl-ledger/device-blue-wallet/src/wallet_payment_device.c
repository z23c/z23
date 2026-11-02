/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "os_io_seproxyhal.h"
#include "blue_payment_apdu.h"
#include "blue_payment_sign.h"
#include "blue_wallet_layout.h"
#include "blue_wallet_signer_device.h"
#include "wallet_payment_device.h"

#include <stdint.h>
#include <string.h>

static union {
    blue_payment_apdu payment;
    wallet_boot_material boot;
} workspace;
static_assert(sizeof workspace.payment >= sizeof workspace.boot);
#define payment workspace.payment
static cx_blake2b_t payment_blake;
static cx_sha256_t payment_sha;
static bool visible;
static uint8_t displayed_view;
static char fee_text[BLUE_PAYMENT_AMOUNT_TEXT_SIZE];
static char others_text[BLUE_PAYMENT_AMOUNT_TEXT_SIZE];
static char own_text[BLUE_PAYMENT_AMOUNT_TEXT_SIZE];
static char input_path_text[16];
static bool totals_view;
static bool sign_review_view, sign_approved_view, sign_complete_view;
static bool declined_view;
static volatile uint32_t payment_epoch;
static uint8_t account_hash160[20];
static uint8_t internal_hash160[20];
static bool account_ready;
static bool command_inflight;

enum { SIGN_APPROVAL_MS = 30000 };

#define TOUCH_PAGE_MASK UINT32_C(0x03ffffff)
#define TOUCH_TARGET_SHIFT 26u
#define TOUCH_TARGET_MASK UINT32_C(0x0f)
#define TOUCH_VALID UINT32_C(0x40000000)
#define TOUCH_SEEN UINT32_C(0x80000000)

/* The low bits count review changes; the high bits bind one finger gesture
 * to its original page and button without allocating more Blue app SRAM. */
static void advance_touch_page(void) {
    uint32_t next = ((payment_epoch & TOUCH_PAGE_MASK) + 1u) &
        TOUCH_PAGE_MASK;
    payment_epoch = next | (payment_epoch & TOUCH_SEEN);
}

static void wipe_bytes(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

wallet_boot_material *wallet_payment_boot_material(void) {
    return &workspace.boot;
}

void wallet_payment_boot_clear(void) {
    wipe_bytes(&workspace.boot, sizeof workspace.boot);
}

void wallet_payment_set_account_hashes(const uint8_t external_hash160[20],
                                       const uint8_t internal_hash[20]) {
    if (!external_hash160 || !internal_hash) return;
    memcpy(account_hash160, external_hash160, sizeof account_hash160);
    memcpy(internal_hash160, internal_hash, sizeof internal_hash160);
    account_ready = true;
}

static bool hash_sha256(const uint8_t *bytes, size_t length,
    uint8_t digest[32]) {
    return length <= UINT32_MAX &&
        cx_hash_sha256(bytes, (unsigned int)length, digest) == 32;
}

static bool final_sign_material_hash(uint8_t digest[32]) {
    uint8_t material[64] = {0};
    bool valid = hash_sha256((const uint8_t *)payment.input_record,
        sizeof payment.input_record, material);
    if (valid) {
        memcpy(material + 32, payment.review.replay.commitment, 32);
        valid = hash_sha256(material, sizeof material, digest);
    }
    wipe_bytes(material, sizeof material);
    if (!valid) wipe_bytes(digest, 32);
    return valid;
}

static bool capture_sign_records(void) {
    static_assert(sizeof payment.screen.address >= 32);
    /* The approved page draws no address; reuse its field until abort. */
    return final_sign_material_hash((uint8_t *)payment.screen.address);
}

static bool sign_records_match(void) {
    uint8_t digest[32] = {0};
    bool matched = final_sign_material_hash(digest) &&
        memcmp(digest, payment.screen.address, sizeof digest) == 0;
    wipe_bytes(digest, sizeof digest);
    return matched;
}

static bool blake_init(void *context, const uint8_t personal[16]) {
    uint8_t copy[16];
    memcpy(copy, personal, sizeof copy);
    return cx_blake2b_init2(context, 256, NULL, 0,
        copy, sizeof copy) == CX_BLAKE2B;
}

static bool hash_update(void *context, const uint8_t *bytes, size_t length) {
    return length <= UINT32_MAX &&
        (cx_hash)(context, 0, bytes, (unsigned int)length, NULL, 0) >= 0;
}

static bool hash_final(void *context, uint8_t digest[32]) {
    return (cx_hash)(context, CX_LAST, NULL, 0, digest, 32) == 32;
}

static bool sha_init(void *context) {
    return cx_sha256_init(context) == CX_SHA256;
}

void wallet_payment_abort(void) {
    advance_touch_page();
    UX_CALLBACK_SET_INTERVAL(0);
    blue_payment_apdu_abort(&payment);
    wipe_bytes(&payment_blake, sizeof payment_blake);
    wipe_bytes(&payment_sha, sizeof payment_sha);
    wipe_bytes(fee_text, sizeof fee_text);
    wipe_bytes(others_text, sizeof others_text);
    wipe_bytes(own_text, sizeof own_text);
    wipe_bytes(input_path_text, sizeof input_path_text);
    visible = false;
    displayed_view = 0;
    totals_view = false;
    sign_review_view = false;
    sign_approved_view = false;
    sign_complete_view = false;
    declined_view = false;
    command_inflight = false;
}

bool wallet_payment_interrupt(void) {
    if (command_inflight) {
        advance_touch_page();
        return false;
    }
    wallet_payment_abort();
    return true;
}

bool wallet_payment_account_ready(void) {
    return account_ready;
}

void wallet_payment_revoke_account(void) {
    wallet_payment_abort();
    wipe_bytes(account_hash160, sizeof account_hash160);
    wipe_bytes(internal_hash160, sizeof internal_hash160);
    account_ready = false;
}

void wallet_payment_boot_reset(void) {
    wallet_payment_revoke_account();
}

bool wallet_payment_visible(void) {
    return visible;
}

bool wallet_payment_timeout(void) {
    if (!visible || (!payment.approved &&
            !(command_inflight && sign_approved_view))) return false;
    if (command_inflight) {
        advance_touch_page();
        return false;
    }
    wallet_payment_abort();
    return true;
}

static void wipe_reply(uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    if (reply) wipe_bytes(reply, capacity);
    if (reply_length) *reply_length = 0;
}

static bool storage_overlaps(const volatile void *left, size_t left_size,
    const volatile void *right, size_t right_size) {
    if (!left || !right || !left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

static bool overlaps_wallet_memory(const void *bytes, size_t length) {
    return storage_overlaps(bytes, length, &workspace, sizeof workspace) ||
        storage_overlaps(bytes, length, &payment_blake,
            sizeof payment_blake) ||
        storage_overlaps(bytes, length, &payment_sha,
            sizeof payment_sha) ||
        storage_overlaps(bytes, length, account_hash160,
            sizeof account_hash160) ||
        storage_overlaps(bytes, length, internal_hash160,
            sizeof internal_hash160) ||
        storage_overlaps(bytes, length, &payment_epoch,
            sizeof payment_epoch);
}

static bool overlaps_wallet_display(const void *bytes, size_t length) {
    return storage_overlaps(bytes, length, fee_text, sizeof fee_text) ||
        storage_overlaps(bytes, length, others_text, sizeof others_text) ||
        storage_overlaps(bytes, length, own_text, sizeof own_text) ||
        storage_overlaps(bytes, length, input_path_text,
            sizeof input_path_text) ||
        storage_overlaps(bytes, length, &visible, sizeof visible) ||
        storage_overlaps(bytes, length, &displayed_view,
            sizeof displayed_view) ||
        storage_overlaps(bytes, length, &totals_view, sizeof totals_view) ||
        storage_overlaps(bytes, length, &sign_review_view,
            sizeof sign_review_view) ||
        storage_overlaps(bytes, length, &sign_approved_view,
            sizeof sign_approved_view) ||
        storage_overlaps(bytes, length, &sign_complete_view,
            sizeof sign_complete_view) ||
        storage_overlaps(bytes, length, &declined_view,
            sizeof declined_view) ||
        storage_overlaps(bytes, length, &account_ready,
            sizeof account_ready);
}

static bool wallet_storage_valid(const uint8_t *apdu, size_t length,
    const uint8_t *reply, size_t capacity, const size_t *reply_length) {
    return !overlaps_wallet_memory(apdu, length) &&
        !overlaps_wallet_memory(reply, capacity) &&
        !overlaps_wallet_memory(reply_length, sizeof *reply_length) &&
        !overlaps_wallet_display(apdu, length) &&
        !overlaps_wallet_display(reply, capacity) &&
        !overlaps_wallet_display(reply_length, sizeof *reply_length) &&
        !storage_overlaps(apdu, length, reply_length,
            sizeof *reply_length) &&
        !storage_overlaps(reply, capacity, reply_length,
            sizeof *reply_length);
}

static uint16_t reject_payment(uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    wipe_reply(reply, capacity, reply_length);
    wallet_payment_abort();
    return 0x6985;
}

static uint16_t reject_locked_payment(uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    wipe_reply(reply, capacity, reply_length);
    wallet_payment_revoke_account();
    return 0x6985;
}

static uint16_t payment_entry_status(const uint8_t *apdu, size_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    if (!wallet_storage_valid(apdu, length, reply, capacity,
            reply_length)) {
        wallet_payment_abort();
        return 0x6f00;
    }
    if (!os_global_pin_is_validated())
        return reject_locked_payment(reply, capacity, reply_length);
    if (!account_ready) return reject_payment(reply, capacity, reply_length);
    return 0x9000;
}

static bool command_interrupted(uint32_t epoch, uint8_t *reply,
    size_t capacity, size_t *reply_length) {
    if (epoch == payment_epoch) return false;
    wipe_reply(reply, capacity, reply_length);
    wallet_payment_abort();
    return true;
}

static bool command_invalidated(uint32_t epoch, uint8_t *reply,
    size_t capacity, size_t *reply_length) {
    if (command_interrupted(epoch, reply, capacity, reply_length))
        return true;
    if (os_global_pin_is_validated()) return false;
    (void)reject_locked_payment(reply, capacity, reply_length);
    return true;
}

static bool reply_valid(uint16_t status, const size_t *reply_length,
    size_t capacity) {
    return status == 0x9000 && reply_length && *reply_length <= capacity;
}

static void erase_completed_signing(bool sign_command) {
    if (!sign_command || !payment.input_count ||
        payment.next_sign_index != payment.input_count) return;
    wallet_payment_abort();
    sign_complete_view = true;
}

static uint16_t complete_payment_reply(bool sign_command,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    erase_completed_signing(sign_command);
    if (!os_global_pin_is_validated())
        return reject_locked_payment(reply, capacity, reply_length);
    visible = true;
    return 0x9000;
}

static bool payment_instruction(const uint8_t *apdu, size_t length,
                                uint8_t instruction) {
    return apdu && length >= 2 && apdu[1] == instruction;
}

static bool sign_bound_digest(void *context, uint8_t path,
    const uint8_t digest[32], uint8_t public_key[33],
    uint8_t signature[BLUE_ECDSA_DER_MAX], size_t *signature_length) {
    return capture_sign_records() &&
        blue_wallet_sign_digest(context, path, digest, public_key,
            signature, signature_length) && sign_records_match();
}

static uint16_t sign_payment_command(const uint8_t *apdu, size_t length,
    blue_payment_owned_hashes *owned, uint8_t *reply,
    size_t capacity, size_t *reply_length) {
    if (payment.approved && !sign_records_match())
        return reject_payment(reply, capacity, reply_length);
    return blue_payment_sign_command(&payment, apdu, length, owned,
        sign_bound_digest, owned, blue_wallet_public_hash160,
        reply, capacity, reply_length);
}

static bool response_invalidated(uint32_t epoch, bool sign_command,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    if (sign_command && payment.approved && !sign_records_match()) {
        (void)reject_payment(reply, capacity, reply_length);
        return true;
    }
    return command_invalidated(epoch, reply, capacity, reply_length);
}

uint16_t wallet_payment_command(const uint8_t *apdu, size_t length,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    uint16_t entry_status = payment_entry_status(apdu, length, reply,
        capacity, reply_length);
    if (entry_status != 0x9000) return entry_status;
    if (payment_instruction(apdu, length, 0x20))
        wallet_payment_abort();
    uint32_t epoch = payment_epoch;
    zcl_zip243_hasher blake = {.context = &payment_blake,
        .init = blake_init, .update = hash_update, .final = hash_final};
    zcl_tx_replay_sha256 sha = {.context = &payment_sha,
        .init = sha_init, .update = hash_update, .final = hash_final};
    blue_payment_owned_hashes owned;
    memcpy(owned.external, account_hash160, sizeof owned.external);
    memcpy(owned.internal, internal_hash160, sizeof owned.internal);
    bool sign_command = payment_instruction(apdu, length, 0x29);
    bool abort_command = payment_instruction(apdu, length, 0x24);
    command_inflight = true;
    uint16_t status = sign_command
        ? sign_payment_command(apdu, length, &owned,
            reply, capacity, reply_length)
        : blue_payment_apdu_handle(&payment, apdu, length,
            reply, capacity, reply_length, &blake, &sha,
            hash_sha256, &owned);
    command_inflight = false;
    if (command_invalidated(epoch, reply, capacity, reply_length))
        return 0x6985;
    if (!reply_valid(status, reply_length, capacity)) {
        wipe_reply(reply, capacity, reply_length);
        wallet_payment_abort();
        return status == 0x9000 ? 0x6f00 : status;
    }
    if (abort_command) {
        wallet_payment_abort();
        epoch = payment_epoch;
    }
    if (sign_command && !payment.approved) UX_CALLBACK_SET_INTERVAL(0);
    if (response_invalidated(epoch, sign_command, reply,
            capacity, reply_length))
        return 0x6985;
    return complete_payment_reply(sign_command, reply, capacity, reply_length);
}

static const bagl_element_t *exit_review(const bagl_element_t *element) {
    (void)element;
    blue_wallet_close();
    return NULL;
}

static const bagl_element_t *continue_review(const bagl_element_t *element);
static const bagl_element_t *show_totals(const bagl_element_t *element);
static const bagl_element_t *show_fee(const bagl_element_t *element);
static const bagl_element_t *show_sign_review(const bagl_element_t *element);
static const bagl_element_t *confirm_review(const bagl_element_t *element);
static const bagl_element_t *approve_sign(const bagl_element_t *element);

static unsigned int output_ui_button(unsigned int mask, unsigned int count) {
    (void)mask;
    (void)count;
    return 0;
}

static unsigned int waiting_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int complete_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int fee_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int totals_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int ended_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int confirmed_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int sign_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int signing_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

static unsigned int signed_ui_button(unsigned int mask, unsigned int count) {
    return output_ui_button(mask, count);
}

#define BODY ZCL_WALLET_COLOR_BODY
#define TEXT ZCL_WALLET_COLOR_TEXT
#define ACCENT ZCL_WALLET_COLOR_ACCENT
#define BACKGROUND { .component = { .type = BAGL_RECTANGLE, .x = 0, .y = 0, \
    .width = 320, .height = 480, .fill = BAGL_FILL, \
    .fgcolor = BODY, .bgcolor = BODY } }
#define LABEL(top, words, font) { .component = { .type = BAGL_LABEL, \
    .x = 20, .y = (top), .width = 280, .height = 32, \
    .fgcolor = TEXT, .bgcolor = BODY, \
    .font_id = (font) | BAGL_FONT_ALIGNMENT_CENTER }, .text = (words) }
#define BUTTON(left, words, action) { .component = { \
    .type = BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, \
    .x = (left), .y = 386, .width = 135, .height = 58, \
    .radius = 6, .fill = BAGL_FILL, .fgcolor = ACCENT, .bgcolor = BODY, \
    .font_id = BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | \
        BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE }, \
    .text = (words), .tap = (action) }

static const bagl_element_t output_ui[] = {
    BACKGROUND,
    LABEL(25, payment.screen.title, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(68, payment.screen.kind, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(115, payment.screen.amount, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(172, "ZCL MAINNET ADDRESS", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    LABEL(208, payment.screen.address_lines[0],
          BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(244, payment.screen.address_lines[1],
          BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(280, payment.screen.address_lines[2],
          BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(331, "DRAFT; NO SIGNING", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    BUTTON(20, "CONTINUE", continue_review),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t waiting_ui[] = {
    BACKGROUND,
    LABEL(70, "REVIEWING ZCL", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(150, "SEND NEXT CHUNK", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    LABEL(205, "NO SIGNING", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t complete_ui[] = {
    BACKGROUND,
    LABEL(90, "CHECKING INPUTS", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(170, "WAIT FOR Z23", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    LABEL(220, "NO SIGNING", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t fee_ui[] = {
    BACKGROUND,
    LABEL(70, "CALCULATED FEE", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(145, fee_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(195, "m/44'/147'/0'", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(232, input_path_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(283, "CHAIN UNCHECKED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(315, "BRANCH UNCHECKED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(347, "NO SIGNING", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    BUTTON(20, "TOTALS", show_totals),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t totals_ui[] = {
    BACKGROUND,
    LABEL(25, "OUTPUT TOTALS", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(75, "OWNER NOT VERIFIED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(110, others_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(165, "MATCHES YOUR KEY", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(200, own_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(250, "FEE", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(280, fee_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(314, "CHAIN UNCHECKED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(339, "BRANCH UNCHECKED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(364, "NO SIGNING", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    BUTTON(20, "BACK", show_fee),
    BUTTON(165, "NEXT", show_sign_review)
};

static const bagl_element_t sign_ui[] = {
    BACKGROUND,
    LABEL(4, "FINAL PAYMENT CHECK", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    LABEL(28, "CHAIN UNCHECKED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(62, "OWNER NOT VERIFIED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(92, others_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(128, "MATCHES YOUR KEY", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(158, own_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(194, "FEE", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(224, fee_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(257, input_path_text, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(283, payment.screen.title, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(309, payment.screen.amount, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(335, payment.screen.kind, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(361, "HOST MAY BROADCAST", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    BUTTON(20, "SIGN ZCL", approve_sign),
    BUTTON(165, "NO SIGN", confirm_review)
};

static const bagl_element_t signing_ui[] = {
    BACKGROUND,
    LABEL(105, "SIGNING APPROVED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(180, "SEND SIGN REQUESTS", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(245, "HOST MAY BROADCAST", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(290, "APPROVAL EXPIRES 30S", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t signed_ui[] = {
    BACKGROUND,
    LABEL(105, "SIGNATURES READY", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(180, "VERIFY IN Z23", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(245, "HOST MAY BROADCAST", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t confirmed_ui[] = {
    BACKGROUND,
    LABEL(105, "REVIEW COMPLETE", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(180, "NO SIGNING", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(245, "EXIT WHEN DONE", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t ended_ui[] = {
    BACKGROUND,
    LABEL(90, "REVIEW ENDED", BAGL_FONT_OPEN_SANS_LIGHT_16_22PX),
    LABEL(170, "NO SIGNING", BAGL_FONT_OPEN_SANS_LIGHT_14px),
    BUTTON(165, "EXIT", exit_review)
};

static const bagl_element_t *touch_elements(size_t *count) {
    switch (displayed_view) {
    case 1: *count = sizeof waiting_ui / sizeof waiting_ui[0];
            return waiting_ui;
    case 2: *count = sizeof output_ui / sizeof output_ui[0];
            return output_ui;
    case 3: *count = sizeof complete_ui / sizeof complete_ui[0];
            return complete_ui;
    case 6: *count = sizeof fee_ui / sizeof fee_ui[0]; return fee_ui;
    case 7: *count = sizeof totals_ui / sizeof totals_ui[0];
            return totals_ui;
    case 8: *count = sizeof confirmed_ui / sizeof confirmed_ui[0];
            return confirmed_ui;
    case 9: *count = sizeof sign_ui / sizeof sign_ui[0]; return sign_ui;
    case 10: *count = sizeof signing_ui / sizeof signing_ui[0];
             return signing_ui;
    case 11: *count = sizeof signed_ui / sizeof signed_ui[0];
             return signed_ui;
    default: *count = sizeof ended_ui / sizeof ended_ui[0];
             return ended_ui;
    }
}

static uint8_t payment_touch_target(unsigned x, unsigned y) {
    if (!visible) return 0;
    size_t count = 0;
    const bagl_element_t *elements = touch_elements(&count);
    uint8_t target = 0;
    for (size_t i = 0; i < count; ++i) {
        const bagl_element_t *element = &elements[i];
        if (!(element->component.type & BAGL_FLAG_TOUCHABLE) ||
            !element->tap) continue;
        ++target;
        if (x >= (unsigned)element->component.x &&
            x < (unsigned)(element->component.x + element->component.width) &&
            y >= (unsigned)element->component.y &&
            y < (unsigned)(element->component.y + element->component.height))
            return target;
    }
    return 0;
}

static void payment_finger_touch(uint32_t state, uint8_t target) {
    if (!visible) {
        payment_epoch = state & TOUCH_PAGE_MASK;
        return;
    }
    if (!(state & TOUCH_SEEN))
        payment_epoch = state | TOUCH_SEEN |
            (target ? TOUCH_VALID : 0u) |
            ((uint32_t)target << TOUCH_TARGET_SHIFT);
    else if (target !=
             ((state >> TOUCH_TARGET_SHIFT) & TOUCH_TARGET_MASK))
        payment_epoch = state & ~TOUCH_VALID;
}

static bool payment_finger_release(uint32_t state, uint8_t target) {
    bool allowed = visible && (state & TOUCH_SEEN) &&
        (state & TOUCH_VALID) && target != 0 &&
        target == ((state >> TOUCH_TARGET_SHIFT) & TOUCH_TARGET_MASK);
    payment_epoch = state & TOUCH_PAGE_MASK;
    return allowed;
}

bool wallet_payment_finger_allowed(const unsigned char *event) {
    if (!event) return false;
    unsigned kind = event[3];
    if (kind != SEPROXYHAL_TAG_FINGER_EVENT_TOUCH &&
        kind != SEPROXYHAL_TAG_FINGER_EVENT_RELEASE) return true;
    uint32_t state = payment_epoch;
    if (!visible && !(state & TOUCH_SEEN)) return true;
    unsigned x = ((unsigned)event[4] << 8) | event[5];
    unsigned y = ((unsigned)event[6] << 8) | event[7];
    uint8_t target = payment_touch_target(x, y);
    if (target > TOUCH_TARGET_MASK) target = 0;
    if (kind == SEPROXYHAL_TAG_FINGER_EVENT_TOUCH) {
        payment_finger_touch(state, target);
        return true;
    }
    return payment_finger_release(state, target);
}

#undef BUTTON
#undef LABEL
#undef BACKGROUND
#undef ACCENT
#undef TEXT
#undef BODY

static void display_output(void) {
    if (!blue_payment_screen_mark_account(&payment.screen,
            &payment.review.output, account_hash160,
            internal_hash160, account_ready)) {
        wallet_payment_abort();
        UX_DISPLAY(ended_ui, NULL);
        return;
    }
    UX_DISPLAY(output_ui, NULL);
}

static void display_fee(void) {
    const char *paths = blue_payment_input_paths_label(payment.input_paths);
    if (!paths || strlen(paths) >= sizeof input_path_text ||
        !blue_payment_amount_text(payment.fee_zat, fee_text)) {
        wallet_payment_abort();
        UX_DISPLAY(ended_ui, NULL);
        return;
    }
    memcpy(input_path_text, paths, strlen(paths) + 1);
    UX_DISPLAY(fee_ui, NULL);
}

static bool format_payment_amounts(void) {
    return payment.own_output_zat <= payment.output_zat &&
        blue_payment_amount_text(payment.output_zat -
            payment.own_output_zat, others_text) &&
        blue_payment_amount_text(payment.own_output_zat, own_text) &&
        blue_payment_amount_text(payment.fee_zat, fee_text);
}

static void display_totals(void) {
    if (!format_payment_amounts()) {
        wallet_payment_abort();
        UX_DISPLAY(ended_ui, NULL);
        return;
    }
    UX_DISPLAY(totals_ui, NULL);
}

static bool format_u32(char *text, size_t capacity, const char *prefix,
    uint32_t value) {
    size_t used = strlen(prefix), digits = 0;
    char reversed[10];
    if (used >= capacity) return false;
    memcpy(text, prefix, used);
    do {
        reversed[digits++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    if (digits >= capacity - used) return false;
    while (digits) text[used++] = reversed[--digits];
    text[used] = 0;
    return true;
}

static void format_branch_id(char branch[24], uint32_t id) {
    static const char hex[] = "0123456789ABCDEF";
    memcpy(branch, "BRANCH 0x", 9);
    for (unsigned i = 0; i < 8; ++i)
        branch[9 + i] = hex[(id >> (28u - 4u * i)) & 15u];
    branch[17] = 0;
}

typedef struct {
    uint64_t output_zat, own_output_zat, fee_zat;
    uint32_t branch_id, lock_time, expiry_height;
    uint8_t input_paths;
} final_display_facts;
static_assert(sizeof(final_display_facts) <= sizeof payment.screen.address);
static_assert(sizeof payment.screen.address_lines >= 32);

static void current_final_facts(final_display_facts *facts) {
    memset(facts, 0, sizeof *facts);
    facts->output_zat = payment.output_zat;
    facts->own_output_zat = payment.own_output_zat;
    facts->fee_zat = payment.fee_zat;
    facts->branch_id = payment.review.replay.branch_id;
    facts->lock_time = payment.review.replay.wire.facts.lock_time;
    facts->expiry_height = payment.review.replay.wire.facts.expiry_height;
    facts->input_paths = payment.input_paths;
}

static bool format_sign_facts(void) {
    if (!payment.review.verified || !payment.fee_ready ||
        payment.review.replay.pass != 4 || payment.previous_active ||
        !format_payment_amounts()) return false;
    format_branch_id(payment.screen.title, payment.review.replay.branch_id);
    const zcl_tx_stream_facts *facts = &payment.review.replay.wire.facts;
    if (!format_u32(payment.screen.kind, sizeof payment.screen.kind,
            "LOCK TIME ", facts->lock_time) ||
        !format_u32(payment.screen.amount, sizeof payment.screen.amount,
            "EXPIRY ", facts->expiry_height)) return false;
    final_display_facts displayed;
    current_final_facts(&displayed);
    /* The final page has no address; its address slot pins the drawn facts. */
    memcpy(payment.screen.address, &displayed, sizeof displayed);
    /* The final page also has no address lines; bind the signing material. */
    return final_sign_material_hash(
        (uint8_t *)payment.screen.address_lines);
}

static bool final_material_matches(void) {
    uint8_t digest[32] = {0};
    bool matched = final_sign_material_hash(digest) &&
        memcmp(digest, payment.screen.address_lines, sizeof digest) == 0;
    wipe_bytes(digest, sizeof digest);
    return matched;
}

static bool text_matches(const char *expected, const char *shown,
    size_t capacity) {
    size_t length = strlen(expected) + 1;
    return length <= capacity && memcmp(expected, shown, length) == 0;
}

static bool final_amounts_match(void) {
    char amount[BLUE_PAYMENT_AMOUNT_TEXT_SIZE];
    const char *paths = blue_payment_input_paths_label(payment.input_paths);
    if (!paths || payment.own_output_zat > payment.output_zat ||
        !text_matches(paths, input_path_text, sizeof input_path_text) ||
        !blue_payment_amount_text(payment.output_zat -
            payment.own_output_zat, amount) ||
        !text_matches(amount, others_text, sizeof others_text) ||
        !blue_payment_amount_text(payment.own_output_zat, amount) ||
        !text_matches(amount, own_text, sizeof own_text) ||
        !blue_payment_amount_text(payment.fee_zat, amount)) return false;
    return text_matches(amount, fee_text, sizeof fee_text);
}

static bool final_chain_facts_match(void) {
    char branch[24], lock[20], expiry[32];
    const zcl_tx_stream_facts *facts = &payment.review.replay.wire.facts;
    format_branch_id(branch, payment.review.replay.branch_id);
    return format_u32(lock, sizeof lock, "LOCK TIME ", facts->lock_time) &&
        format_u32(expiry, sizeof expiry, "EXPIRY ",
            facts->expiry_height) &&
        text_matches(branch, payment.screen.title,
            sizeof payment.screen.title) &&
        text_matches(lock, payment.screen.kind,
            sizeof payment.screen.kind) &&
        text_matches(expiry, payment.screen.amount,
            sizeof payment.screen.amount);
}

static bool final_screen_matches_payment(void) {
    final_display_facts current;
    current_final_facts(&current);
    return displayed_view == 9 && payment.review.verified &&
        payment.fee_ready && payment.review.replay.pass == 4 &&
        !payment.previous_active &&
        memcmp(payment.screen.address, &current, sizeof current) == 0 &&
        final_material_matches() &&
        final_amounts_match() &&
        final_chain_facts_match();
}

static uint8_t payment_view(void) {
    return declined_view ? 8 :
        sign_complete_view ? 11 :
        sign_approved_view ? 10 :
        sign_review_view ? 9 :
        payment.review.pending ? 2 :
        payment.fee_ready ? (totals_view ? 7 : 6) :
        payment.review.verified ? 3 :
        payment.active ? 1 : 4;
}

void wallet_payment_display(void) {
    if (visible && !os_global_pin_is_validated()) {
        wallet_payment_revoke_account();
        UX_DISPLAY(ended_ui, NULL);
        return;
    }
    uint8_t view = payment_view();
    if (view == displayed_view) return;
    advance_touch_page();
    displayed_view = view;
    if (view == 2) display_output();
    else if (view == 8) { UX_DISPLAY(confirmed_ui, NULL); }
    else if (view == 6) display_fee();
    else if (view == 7) display_totals();
    else if (view == 9) {
        if (format_sign_facts()) {
            UX_DISPLAY(sign_ui, NULL);
        } else {
            wallet_payment_abort();
            UX_DISPLAY(ended_ui, NULL);
        }
    }
    else if (view == 10) { UX_DISPLAY(signing_ui, NULL); }
    else if (view == 11) { UX_DISPLAY(signed_ui, NULL); }
    else if (view == 3) { UX_DISPLAY(complete_ui, NULL); }
    else if (view == 1) { UX_DISPLAY(waiting_ui, NULL); }
    else { UX_DISPLAY(ended_ui, NULL); }
}

static const bagl_element_t *show_totals(const bagl_element_t *element) {
    (void)element;
    if (visible && payment.fee_ready && !payment.review_confirmed &&
        !totals_view) {
        totals_view = true;
        displayed_view = 0;
        wallet_payment_display();
    }
    return NULL;
}

static const bagl_element_t *show_fee(const bagl_element_t *element) {
    (void)element;
    if (visible && payment.fee_ready && !payment.review_confirmed &&
        totals_view && !sign_review_view) {
        totals_view = false;
        displayed_view = 0;
        wallet_payment_display();
    }
    return NULL;
}

static const bagl_element_t *show_sign_review(const bagl_element_t *element) {
    (void)element;
    if (visible && payment.fee_ready && totals_view &&
        !payment.review_confirmed && !sign_review_view) {
        sign_review_view = true;
        displayed_view = 0;
        wallet_payment_display();
    }
    return NULL;
}

static const bagl_element_t *confirm_review(const bagl_element_t *element) {
    (void)element;
    if (declined_view || sign_approved_view) return NULL;
    if (!sign_review_view || !totals_view ||
        !blue_payment_apdu_touch_confirm(&payment)) {
        wallet_payment_abort();
        UX_DISPLAY(ended_ui, NULL);
        return NULL;
    }
    wallet_payment_abort();
    declined_view = true;
    visible = true;
    wallet_payment_display();
    return NULL;
}

static const bagl_element_t *approve_sign(const bagl_element_t *element) {
    (void)element;
    if (sign_approved_view || declined_view) return NULL;
    if (!os_global_pin_is_validated()) {
        wallet_payment_revoke_account();
        UX_DISPLAY(ended_ui, NULL);
        return NULL;
    }
    if (!sign_review_view || !totals_view ||
        !final_screen_matches_payment() ||
        !blue_payment_apdu_touch_approve(&payment) ||
        !capture_sign_records()) {
        wallet_payment_abort();
        UX_DISPLAY(ended_ui, NULL);
        return NULL;
    }
    sign_approved_view = true;
    UX_CALLBACK_SET_INTERVAL(SIGN_APPROVAL_MS);
    displayed_view = 0;
    wallet_payment_display();
    return NULL;
}

static const bagl_element_t *continue_review(const bagl_element_t *element) {
    (void)element;
    if (!visible || !payment.active || !payment.review.pending) return NULL;
    blue_payment_screen expected;
    bool matches = displayed_view == 2 &&
        blue_payment_screen_format(&payment.review.output,
            payment.review.total_outputs, hash_sha256, &expected) &&
        blue_payment_screen_mark_account(&expected, &payment.review.output,
            account_hash160, internal_hash160, account_ready) &&
        memcmp(&expected, &payment.screen, sizeof expected) == 0;
    if (!matches) {
        wallet_payment_abort();
        UX_DISPLAY(ended_ui, NULL);
        return NULL;
    }
    blue_payment_owned_hashes owned;
    memcpy(owned.external, account_hash160, sizeof owned.external);
    memcpy(owned.internal, internal_hash160, sizeof owned.internal);
    if (!account_ready || !blue_payment_apdu_touch_continue(&payment, &owned)) {
        wallet_payment_abort();
        UX_DISPLAY(ended_ui, NULL);
        return NULL;
    }
    wallet_payment_display();
    return NULL;
}
