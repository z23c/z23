/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_GAME_VIEW_H
#define ZAPP_GAME_VIEW_H
#include <android/input.h>
#include <jni.h>
#include <stdbool.h>
bool zapp_game_view_create(JNIEnv *env, jobject activity, jobject root);
void zapp_game_view_render(JNIEnv *env);
void zapp_game_view_clear(JNIEnv *env);
void zapp_game_view_touch(JNIEnv *env, const AInputEvent *event);
void zapp_game_view_destroy(JNIEnv *env);
#endif
