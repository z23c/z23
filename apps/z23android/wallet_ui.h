/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_UI_H
#define ZAPP_WALLET_UI_H
#include "wallet_screens.h"
#include <android/native_activity.h>
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

/* Draws the wallet screens into platform widgets and carries taps back to wallet_screens.c. This file
 * holds no wallet state of its own beyond the copy of the screen it is drawing, which clear wipes. */

/* Binds the wallet screens to the activity: screen protection, the node commands, and a callback that
 * wakes the UI thread when a reply changes a screen. Call once the controller is running. */
bool zapp_wallet_attach(ANativeActivity *activity, void (*changed)(void));
void zapp_wallet_detach(void);

/* container is a vertical LinearLayout inside the wallet screen's ScrollView. */
bool zapp_wallet_ui_create(JNIEnv *env, jobject activity, jobject container);
void zapp_wallet_ui_destroy(JNIEnv *env);
/* Redraws when the screen changed since the last draw. */
void zapp_wallet_ui_render(JNIEnv *env);
/* Removes every widget and wipes the copy of the screen. */
void zapp_wallet_ui_clear(JNIEnv *env);
/* Asks the screens to refresh what is due, then redraws. Call about every two seconds while a wallet screen is in front. */
void zapp_wallet_ui_tick(JNIEnv *env);
/* A touch was dropped because another window was drawing over the app: tells the screen and redraws.
 * shell_drops is the shell's own count of such touches; the window gate's is read here. */
void zapp_wallet_ui_dropped(JNIEnv *env, unsigned shell_drops);
/* The button under a window point, or false. */
bool zapp_wallet_ui_hit(JNIEnv *env, float x, float y, size_t *button);
/* Performs the button, then redraws. */
enum wallet_outcome zapp_wallet_ui_press(JNIEnv *env, size_t button);
#endif
