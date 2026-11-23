/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_REVIEW_H
#define ZAPP_REVIEW_H
#include <jni.h>
#include <stdbool.h>
/* These entry points are called only on the Android main looper. */
bool zapp_review_is_pending(void);
bool zapp_review_is_activity(JNIEnv *env, jobject activity);
bool zapp_review_begin(JNIEnv *env, jobject activity);
bool zapp_review_picker_result(JNIEnv *env, jobject activity, jint result, jobject data);
#endif
