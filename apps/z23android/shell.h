/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SHELL_H
#define ZAPP_SHELL_H
#include "app.h"
#include "native_ui.h"

/* The phone's Home: a stage holding the layout-drawn home screen, the apps and settings screens, the
 * scan camera screen and the assistant tree built by native_ui. Back from any screen returns to the
 * home screen. The apps and settings screens and their entry points are drawn by app code, so no
 * layout can remove them. */
bool zapp_shell_create(JNIEnv *env, jobject activity, jobject assistant, bool preview);
void zapp_shell_destroy(JNIEnv *env);
void zapp_shell_render(JNIEnv *env, const struct zapp_view *view);
/* Handles taps on shell screens and the Back key; true when the event was consumed. */
bool zapp_shell_input(JNIEnv *env, const AInputEvent *event);
/* Whether the assistant tree is the screen in front. */
bool zapp_shell_assistant(void);
/* On resume: hides the system bars again, re-reads the app list and the layout file. */
void zapp_shell_resume(JNIEnv *env);
void zapp_shell_immersive(JNIEnv *env);
/* A camera frame for the scan screen; NULL clears it. */
void zapp_shell_preview(JNIEnv *env, const unsigned char *bmp, size_t len);
/* A message under the home screen's top edge until the next screen change. */
void zapp_shell_notice(JNIEnv *env, const char *text);
#endif
