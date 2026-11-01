/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_UI_H
#define ZAPP_WALLET_SEND_UI_H
#include "payment_code.h"
#include <android/native_activity.h>
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

/* The Send screen: it draws the send flow of wallet_send_screen.c as Android Views and carries taps back to it. It
 * also wires that flow to the app: the node commands through the controller, the device key on a worker thread that is
 * attached to the JVM, the clock, a random source and the window protection.
 *
 * Send is drawn as a View with setFilterTouchesWhenObscured, and the shell drops obscured touches natively as well.
 * The payment reaches this file only through zapp_send_ui_open, from the one-slot holder of pay_stash.c; it is never
 * in the app's view. This file logs nothing. */

enum zapp_send_outcome {
    ZAPP_SEND_STAY,  /* the screen changed or nothing happened */
    ZAPP_SEND_SCAN,  /* open the camera scan screen */
    ZAPP_SEND_LEAVE  /* the flow is over: go Home */
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
/* Opens the screen on a payment, or, with none, on a notice with Scan code and Enter address. */
void zapp_send_ui_open(JNIEnv *env, const struct zapp_payment *pay, const char *notice);
/* Redraws when what is shown changed since the last draw. */
void zapp_send_ui_render(JNIEnv *env);
/* Removes every widget and wipes the copy of the screen. */
void zapp_send_ui_clear(JNIEnv *env);
/* Call about every two seconds for as long as the app runs, on or off this screen: ticks are what ask again for a lock
 * that is owed. */
void zapp_send_ui_tick(JNIEnv *env);
/* True while the flow holds, or may hold, the wallet open: the app keeps ticking. */
bool zapp_send_ui_owes(void);
/* True once after the app attached to a flow kept from an earlier activity: the shell shows the Send screen. */
bool zapp_send_ui_take_reshow(void);
/* The app left the foreground. */
void zapp_send_ui_pause(void);
/* The owner leaves the screen. False while a payment is being built or the wallet is still open: the screen stays. */
bool zapp_send_ui_leave(JNIEnv *env);
/* A touch was dropped because another window was drawing over the app. */
void zapp_send_ui_dropped(JNIEnv *env);
/* The button under a window point, or false. */
bool zapp_send_ui_hit(JNIEnv *env, float x, float y, size_t *button);
/* Performs the button, then redraws. */
enum zapp_send_outcome zapp_send_ui_press(JNIEnv *env, size_t button);

#endif
