/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_JNI_UTIL_H
#define ZAPP_JNI_UTIL_H
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

/* Shared JNI idioms of the native screens. Each call clears a pending Java exception and reports
 * failure as false or NULL; local references it creates are released before it returns, except the
 * object it hands back. */
bool zj_clean(JNIEnv *env);
void zj_set_density(float density);
int zj_dp(float value);
jmethodID zj_method(JNIEnv *env, jobject obj, const char *name, const char *sig);
jobject zj_object_property(JNIEnv *env, jobject obj, const char *name, const char *sig);
bool zj_int_property(JNIEnv *env, jobject view, const char *name, jint value);
bool zj_bool_property(JNIEnv *env, jobject view, const char *name, bool value);
bool zj_padding(JNIEnv *env, jobject view, int horizontal_dp, int vertical_dp);
bool zj_padding4(JNIEnv *env, jobject view, int left, int top, int right, int bottom);
bool zj_typography(JNIEnv *env, jobject view, float sp, jint color);
jobject zj_widget(JNIEnv *env, const char *type, jobject activity);
jstring zj_string(JNIEnv *env, const char *value);
bool zj_char_sequence(JNIEnv *env, jobject view, const char *method, const char *value);
bool zj_text(JNIEnv *env, jobject view, const char *value);
bool zj_append(JNIEnv *env, jobject group, jobject view);
bool zj_keep(JNIEnv *env, jobject *dest, jobject value);
bool zj_visible(JNIEnv *env, jobject view, bool visible);
bool zj_pill(JNIEnv *env, jobject view, jint color, float radius_dp);
bool zj_flatten(JNIEnv *env, jobject view);
/* Gives a child of a LinearLayout its size (pixels or a LayoutParams constant), weight and margins. */
bool zj_margins(JNIEnv *env, jobject view, int width, int height, float weight, int left_dp, int top_dp, int right_dp, int bottom_dp);
bool zj_place(JNIEnv *env, jobject view, int width, int height, float weight, int bottom_dp);
/* Whether a window point lies inside a shown view. */
bool zj_hit(JNIEnv *env, jobject view, float x, float y);
/* Copies a Java string as UTF-8; false when it does not fit in cap. */
bool zj_copy_utf(JNIEnv *env, jstring value, char *out, size_t cap);
/* Shows a BMP or other image encoding in an ImageView; a NULL image clears it. */
bool zj_bitmap(JNIEnv *env, jobject view, const unsigned char *bmp, size_t len);
#endif
