/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SETUP_UI_H
#define ZAPP_WALLET_SETUP_UI_H
#include <android/native_activity.h>
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

/* The first-run setup screens: Create or Restore, the recovery words shown once, the words asked back, and the progress
 * of a restore, drawn as Android Views over the model of wallet_setup.c. The device key and the node commands run on a
 * worker thread attached to the JVM; the UI thread only draws and reads fields.
 *
 * The words are drawn only while the window carries every protection of secure_window.h (no screenshots, no recents
 * thumbnail, no overlay, no accessibility readout). They are removed from the view tree whenever the app leaves the
 * foreground. This file logs nothing. */

enum zapp_setup_outcome {
    ZAPP_SETUP_STAY,
    ZAPP_SETUP_LEAVE   /* setup is finished or the owner went back: go Home */
};

/* Binds setup to the activity. changed wakes the UI thread when the model changed what is shown. */
bool zapp_setup_attach(ANativeActivity *activity, void (*changed)(void));
/* container is a vertical LinearLayout inside the setup screen's ScrollView. */
bool zapp_setup_ui_create(JNIEnv *env, jobject activity, jobject container);
void zapp_setup_ui_destroy(JNIEnv *env);
/* Starts the model from the files on disk on first use and applies the window protection. False when this phone cannot
 * protect the window: no wallet content is shown then. */
bool zapp_setup_ui_open(JNIEnv *env);
void zapp_setup_ui_render(JNIEnv *env);
/* Removes every widget and wipes the copy of the screen. */
void zapp_setup_ui_clear(JNIEnv *env);
/* About every two seconds while the screen is up: asks the node how far a restore has read. */
void zapp_setup_ui_tick(JNIEnv *env);
/* The app left the foreground: the words leave the view tree. */
void zapp_setup_ui_pause(JNIEnv *env);
/* The owner leaves the screen. False while a job runs or the words are held. */
bool zapp_setup_ui_leave(JNIEnv *env);
void zapp_setup_ui_dropped(JNIEnv *env);
/* The button under the point: its position, and the identity of what it does, so a screen that redraws between the press and the
 * release does not run the button that moved into the same position. */
bool zapp_setup_ui_hit(JNIEnv *env, float x, float y, size_t *button, unsigned *id);
enum zapp_setup_outcome zapp_setup_ui_press(JNIEnv *env, size_t button);

#endif
