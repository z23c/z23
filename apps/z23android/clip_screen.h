/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CLIP_SCREEN_H
#define ZAPP_CLIP_SCREEN_H
#include <android/input.h>
#include <jni.h>
#include <stdbool.h>

/* Full-screen recording and watching, drawn by app code over the activity. All calls run on the
 * activity's main thread. */
enum zapp_clip_mode { ZAPP_CLIP_RECORD, ZAPP_CLIP_WATCH };

/* Opens the screen over the activity; files_dir is the app's internal files directory. */
bool zapp_clip_screen_open(JNIEnv *env, jobject activity, const char *files_dir, enum zapp_clip_mode mode);
bool zapp_clip_screen_active(void);

/* True when the screen handled the back key; false when it is not showing. */
bool zapp_clip_screen_back(JNIEnv *env);
void zapp_clip_screen_close(JNIEnv *env);

/* Touch and key events from the activity's input queue; true when the screen consumed the event. */
bool zapp_clip_screen_input(JNIEnv *env, const AInputEvent *event);

/* Activity lifecycle: pause stops a recording cleanly and releases the camera and decoders; resume
 * checks the permissions the person was asked for. */
void zapp_clip_screen_pause(JNIEnv *env);
void zapp_clip_screen_resume(JNIEnv *env);
#endif
