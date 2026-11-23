/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SHARE_H
#define ZAPP_SHARE_H
#include <jni.h>
#include <stdbool.h>

#define ZAPP_SHARE_PICK_REQUEST 0x5a23
#define ZAPP_SHARE_SEND_REQUEST 0x5a24
#define ZAPP_REVIEW_PICK_REQUEST 0x5a25
/* Retains the current Receive code for media sharing, or refuses a share already pending. */
bool zapp_share_prepare(void);
bool zapp_share_busy(void);
/* Retains the current Receive code for direct text sharing, or refuses a share already pending. */
bool zapp_share_prepare_text(void);
/* Opens the picker for media, or Android's recipient chooser directly for text. No data is shared yet. */
bool zapp_share_begin(JNIEnv *env, jobject activity);
/* Offers text or picked media and code through Android's share sheet, or reports a cancellation/failure.
 * Returns true to close ShareActivity, or false to leave it open for the chooser result. */
bool zapp_share_result(JNIEnv *env, jobject activity, jint request, jint result, jobject data);
/* Returns once to Receive when the app-owned share activity closes, with a non-sensitive notice to show there. */
bool zapp_share_take_result(char *out, size_t cap);
/* Review is separate from payment sharing and never starts the node. */
bool zapp_review_prepare(void);
void zapp_review_abandon(void);
void zapp_review_snapshot(char *out, size_t cap);
bool zapp_review_take_return(void);
/* DEX entry points for sharing and its result. */
JNIEXPORT void JNICALL Java_org_z23_nativeapp_ShareActivity_shareCreate(JNIEnv *, jobject);
JNIEXPORT jint JNICALL Java_org_z23_nativeapp_ShareActivity_shareResultNative(JNIEnv *, jobject, jint, jint, jobject);
/* Wipes the pending payment code. */
void zapp_share_destroy(void);
#endif
