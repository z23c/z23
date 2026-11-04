/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_UI_H
#define ZAPP_WALLET_SEND_UI_H
#include "payment_code.h"
#include <android/native_activity.h>
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The Send screen: it draws the send flow of wallet_send_screen.c as Android Views and carries taps back to it. It
 * also wires that flow to the app: the node commands through the controller, the device key on a worker thread that is
 * attached to the JVM, the clock, a random source and the window protection.
 *
 * Send is drawn as a View with setFilterTouchesWhenObscured, and the shell drops obscured touches natively as well.
 * The payment reaches this file only through zapp_send_ui_open, from the one-slot holder of pay_stash.c; it is never
 * in the app's view. This file logs nothing. */

enum zapp_send_outcome {
    ZAPP_SEND_STAY,  /* the screen changed or nothing happened */
    ZAPP_SEND_SCAN,    /* open the camera scan screen */
    ZAPP_SEND_LEAVE,   /* the flow is over: go Home */
    ZAPP_SEND_RECEIVE  /* nothing to send: open Receive on the wallet screen */
};

/* Binds the Send flow to the activity. Call once the controller is running. changed wakes the UI thread when the flow
 * changed what is shown. */
bool zapp_send_attach(ANativeActivity *activity, void (*changed)(void));
/* Ends the flow if the wallet is not open, and otherwise keeps asking for the lock for a short while; a flow that is
 * still locking is released by the next attach. */
void zapp_send_detach(JNIEnv *env);

/* container is a vertical LinearLayout inside the Send screen's ScrollView. */
bool zapp_send_ui_create(JNIEnv *env, jobject activity, jobject container);
void zapp_send_ui_destroy(JNIEnv *env);
/* Opens the screen on a payment, or, with none, on the start page of wss_start_page under the notice: Scan code, the
 * address field with its keyboard open and Paste address when the clipboard holds an address, or, with a balance known to
 * be 0, the line that says so and Receive. */
void zapp_send_ui_open(JNIEnv *env, const struct zapp_payment *pay, const char *notice);
/* The spendable balance the wallet screen read moments ago. Call before zapp_send_ui_open, so the start page shows a zero
 * balance at once. */
void zapp_send_ui_known_balance(uint64_t spendable_zat);
/* The window regained focus: the start page looks at the clipboard again, for an address copied in another app. */
void zapp_send_ui_focus(JNIEnv *env);
/* Opens the screen on the move of public funds into the private balance (Make private on Funds). The node names the amount,
 * so nothing is passed; the review, the screen lock and the commit are the payment's. */
void zapp_send_ui_open_sweep(JNIEnv *env);
/* Redraws when what is shown changed since the last draw. */
void zapp_send_ui_render(JNIEnv *env);
/* Removes every widget and wipes the copy of the screen. */
void zapp_send_ui_clear(JNIEnv *env);
/* Call about every two seconds for as long as the app runs, on or off this screen: ticks are what ask again for a lock
 * that is owed. */
void zapp_send_ui_tick(JNIEnv *env);
/* True while the flow holds, or may hold, the wallet open: the app keeps ticking. */
bool zapp_send_ui_owes(void);
/* True from the owner's confirmation of a payment until its outcome (see wss_send_busy). Any thread may call it. */
bool zapp_send_busy(void);
/* True once after the app attached to a flow kept from an earlier activity: the shell shows the Send screen. */
bool zapp_send_ui_take_reshow(void);
/* The app left the foreground. */
void zapp_send_ui_pause(void);
/* The owner leaves the screen. False while a payment is being built or the wallet is still open: the screen stays. */
bool zapp_send_ui_leave(JNIEnv *env);
/* True once per payment, when the commit starts while the Send screen is shown: the shell then goes to the wallet
 * screen and the payment goes on in the background. The screen can be left (zapp_send_ui_leave succeeds) while it runs. */
bool zapp_send_ui_take_background(void);
/* The one line the wallet screen draws for a payment from the owner's confirmation on, for example
 * "Sending 1.5 ZCL to zs1abcde…uvwxyz: building the payment (about 2 min)", then "…: waiting to leave the phone", then
 * "Sent 1.5 ZCL", or "Payment not sent: <cause>. Your coins were not spent." Kept after the payment ended until the next
 * payment begins or zapp_send_progress_dismiss. False when there is nothing to say. Call on the UI thread. */
bool zapp_send_progress(char *line, size_t cap);
void zapp_send_progress_dismiss(void);
/* A touch was dropped because another window was drawing over the app. */
void zapp_send_ui_dropped(JNIEnv *env);
/* The button under a window point, or false. */
bool zapp_send_ui_hit(JNIEnv *env, float x, float y, size_t *button, unsigned *id);
/* The button the keyboard's action key presses: Set amount (or Change amount) from the amount field, Use this address from
 * the address field; false when neither field has the focus. */
bool zapp_send_ui_field_button(JNIEnv *env, size_t *button);
/* Performs the button, then redraws. */
enum zapp_send_outcome zapp_send_ui_press(JNIEnv *env, size_t button);

#endif
