/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_shielded_review_app.h"

#include <string.h>

_Static_assert(sizeof "SEND SHIELDED TRANSACTION" <= ZCL_BLUE_REVIEW_LINE_SIZE,
    "every reset line literal fits a review line");

static bool overlap(const void *left, size_t left_size,
    const void *right, size_t right_size) {
    if (!left || !right || !left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_size : a - b < right_size;
}

static void clear_external_reply(uint8_t *reply, size_t capacity,
    size_t *reply_length) {
    if (reply) {
        volatile uint8_t *bytes = reply;
        for (size_t i = 0; i < capacity; ++i) bytes[i] = 0;
    }
    if (reply_length) *reply_length = 0;
}

void blue_shielded_review_app_reset(blue_shielded_review_app *app) {
    if (!app) return;
    blue_shielded_review_abort(&app->transaction);
    memset(app->reply, 0, sizeof app->reply);
    memset(app->lines, 0, sizeof app->lines);
    app->detail = app->page = 0;
    memcpy(app->lines[0], "CONNECT Z23", sizeof "CONNECT Z23");
    memcpy(app->lines[1], "SEND SHIELDED TRANSACTION",
        sizeof "SEND SHIELDED TRANSACTION");
    memcpy(app->lines[2], "READ ONLY; NO SIGNING",
        sizeof "READ ONLY; NO SIGNING");
}

static bool show_progress(blue_shielded_review_app *app) {
    zcl_tx_shielded_replay *review = &app->transaction.replay;
    app->page = app->detail = 0;
    return blue_review_screen_progress(review->pass,
        review->wire.received, review->expected, app->lines);
}

static bool show_summary(blue_shielded_review_app *app) {
    app->page = app->detail = 0;
    return blue_review_screen_zip243(app->reply, app->lines);
}

static bool command_buffers_valid(const blue_shielded_review_app *app,
    const uint8_t *apdu, size_t apdu_length,
    const uint8_t *reply, size_t capacity, const size_t *reply_length) {
    return app && apdu && reply && reply_length &&
        !overlap(app, sizeof *app, apdu, apdu_length) &&
        !overlap(app, sizeof *app, reply, capacity) &&
        !overlap(app, sizeof *app, reply_length, sizeof *reply_length);
}

static uint16_t reject_command(blue_shielded_review_app *app,
    uint8_t *reply, size_t capacity, size_t *reply_length) {
    bool external_reply = !overlap(app, sizeof *app, reply, capacity);
    bool external_length = !overlap(app, sizeof *app,
        reply_length, sizeof *reply_length);
    blue_shielded_review_app_reset(app);
    clear_external_reply(external_reply ? reply : NULL, capacity,
        external_length ? reply_length : NULL);
    return 0x6a80;
}

uint16_t blue_shielded_review_app_command(blue_shielded_review_app *app,
    const uint8_t *apdu, size_t apdu_length, uint8_t *reply,
    size_t reply_capacity, size_t *reply_length,
    const zcl_zip243_hasher *hasher) {
    if (!command_buffers_valid(app, apdu, apdu_length, reply,
            reply_capacity, reply_length))
        return reject_command(app, reply, reply_capacity, reply_length);
    uint8_t instruction = apdu_length >= 2 ? apdu[1] : 0;
    uint16_t status = blue_shielded_review_handle(&app->transaction,
        apdu, apdu_length, reply, reply_capacity, reply_length, hasher);
    if (status != 0x9000) {
        blue_shielded_review_app_reset(app);
        return status;
    }
    bool formatted = true;
    if (instruction == 0x20 || instruction == 0x21 ||
        instruction == 0x22) formatted = show_progress(app);
    else if (instruction == 0x23) {
        formatted = *reply_length == sizeof app->reply;
        if (formatted) {
            memcpy(app->reply, reply, sizeof app->reply);
            formatted = show_summary(app);
        }
    } else if (instruction == 0x24)
        blue_shielded_review_app_reset(app);
    if (formatted) return status;
    blue_shielded_review_app_reset(app);
    clear_external_reply(reply, reply_capacity, reply_length);
    return 0x6a80;
}

bool blue_shielded_review_app_next(blue_shielded_review_app *app) {
    if (!app) return false;
    if (app->large_text) {
        for (unsigned next = (unsigned)app->detail + 1;
             next < ZCL_BLUE_REVIEW_LINES; ++next)
            if (app->lines[next][0]) {
                app->detail = (uint8_t)next;
                return true;
            }
    }
    if (!app->transaction.complete) {
        app->detail = 0;
        return false;
    }
    app->page = (uint8_t)((app->page + 1u) % 3u);
    app->detail = 0;
    if (app->page == 2)
        return blue_review_screen_wire_commitment(app->reply + 76,
            app->lines);
    return app->page == 1 ?
        blue_review_screen_zip243_digest(app->reply + 44,
            app->transaction.branch_id, app->lines) :
        blue_review_screen_zip243(app->reply, app->lines);
}

void blue_shielded_review_app_toggle_text(blue_shielded_review_app *app) {
    if (!app) return;
    app->large_text = !app->large_text;
    app->detail = 0;
}

void blue_shielded_review_app_toggle_dark(blue_shielded_review_app *app) {
    if (app) app->dark = !app->dark;
}
