/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SHARE_H
#define ZAPP_SHARE_H
#include <jni.h>
#include <stdbool.h>

#define ZAPP_SHARE_PICK_REQUEST 0x5a23
/* Retains the current Receive code for the generated ShareActivity, or refuses a share already pending. */
bool zapp_share_prepare(void);
/* Opens the system image/video picker from the generated ShareActivity. No data is shared yet. */
bool zapp_share_begin(JNIEnv *env, jobject activity);
/* Offers the picked media and code through Android's share sheet, or reports a cancellation/failure. */
void zapp_share_result(JNIEnv *env, jobject activity, jint request, jint result, jobject data);
/* Returns once to Receive when the app-owned share activity closes, with a non-sensitive notice to show there. */
bool zapp_share_take_result(char *out, size_t cap);
/* DEX entry points for picker creation and its result. */
JNIEXPORT void JNICALL Java_org_z23_nativeapp_ShareActivity_shareCreate(JNIEnv *, jobject);
JNIEXPORT void JNICALL Java_org_z23_nativeapp_ShareActivity_shareResultNative(JNIEnv *, jobject, jint, jint, jobject);
/* Wipes the pending payment code. */
void zapp_share_destroy(void);
#endif
