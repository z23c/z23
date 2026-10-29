/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_NATIVE_UI_H
#define Z23_NATIVE_UI_H
#include "app.h"
#include <android/input.h>
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

typedef void (*zapp_native_action)(const char *action, const char *text);
/* Whether this is the voice preview package, which never runs a node. */
bool zapp_native_ui_package_preview(JNIEnv *env, jobject activity, bool *preview);
bool zapp_native_ui_create(JNIEnv *env, jobject activity, zapp_native_action action);
void zapp_native_ui_destroy(JNIEnv *env);
void zapp_native_ui_input(JNIEnv *env, const AInputEvent *event);
void zapp_native_ui_update(JNIEnv *env, const char *status, const char *output);
void zapp_native_ui_render(JNIEnv *env, const struct zapp_view *view);
void zapp_native_ui_preview(JNIEnv *env, const unsigned char *bmp, size_t len);
#endif
