/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jni_util.h"
#include <string.h>

static float density = 1.0f;

bool zj_clean(JNIEnv *env)
{
    if (!(*env)->ExceptionCheck(env)) return true;
    (*env)->ExceptionClear(env); return false;
}
void zj_set_density(float value) { density = value; }
int zj_dp(float value) { return (int)(value * density + 0.5f); }
/* Looks up a method on the object's class and releases the class reference. */
jmethodID zj_method(JNIEnv *env, jobject obj, const char *name, const char *sig)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID method = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, name, sig) : NULL;
    bool found = zj_clean(env) && method;
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return found ? method : NULL;
}
jobject zj_object_property(JNIEnv *env, jobject obj, const char *name, const char *sig)
{
    jmethodID method = zj_method(env, obj, name, sig);
    jobject value = method ? (*env)->CallObjectMethod(env, obj, method) : NULL;
    return zj_clean(env) ? value : NULL;
}
bool zj_int_property(JNIEnv *env, jobject view, const char *name, jint value)
{
    jmethodID method = zj_method(env, view, name, "(I)V");
    if (!method) return false;
    (*env)->CallVoidMethod(env, view, method, value);
    return zj_clean(env);
}
bool zj_bool_property(JNIEnv *env, jobject view, const char *name, bool value)
{
    jmethodID method = zj_method(env, view, name, "(Z)V");
    if (!method) return false;
    (*env)->CallVoidMethod(env, view, method, (jboolean)value);
    return zj_clean(env);
}
bool zj_padding4(JNIEnv *env, jobject view, int left, int top, int right, int bottom)
{
    jmethodID set = zj_method(env, view, "setPadding", "(IIII)V");
    if (!set) return false;
    (*env)->CallVoidMethod(env, view, set, zj_dp((float)left), zj_dp((float)top), zj_dp((float)right), zj_dp((float)bottom));
    return zj_clean(env);
}
bool zj_padding(JNIEnv *env, jobject view, int horizontal_dp, int vertical_dp)
{
    return zj_padding4(env, view, horizontal_dp, vertical_dp, horizontal_dp, vertical_dp);
}
bool zj_typography(JNIEnv *env, jobject view, float sp, jint color)
{
    jmethodID size = zj_method(env, view, "setTextSize", "(F)V");
    if (!size) return false;
    (*env)->CallVoidMethod(env, view, size, sp);
    return zj_clean(env) && zj_int_property(env, view, "setTextColor", color);
}
jobject zj_widget(JNIEnv *env, const char *type, jobject activity)
{
    jclass cls = (*env)->FindClass(env, type);
    if (!zj_clean(env) || !cls) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(Landroid/content/Context;)V");
    jobject obj = ctor ? (*env)->NewObject(env, cls, ctor, activity) : NULL;
    if (!zj_clean(env)) obj = NULL;
    (*env)->DeleteLocalRef(env, cls); return obj;
}
jstring zj_string(JNIEnv *env, const char *value)
{
    size_t length = strlen(value);
    jclass cls = (*env)->FindClass(env, "java/lang/String");
    jmethodID ctor = cls ? (*env)->GetMethodID(env, cls, "<init>", "([BLjava/lang/String;)V") : NULL;
    jbyteArray bytes = length <= 65536 ? (*env)->NewByteArray(env, (jsize)length) : NULL;
    jstring encoding = (*env)->NewStringUTF(env, "UTF-8");
    if (bytes) (*env)->SetByteArrayRegion(env, bytes, 0, (jsize)length, (const jbyte *)value);
    jstring result = zj_clean(env) && ctor && bytes && encoding ? (*env)->NewObject(env, cls, ctor, bytes, encoding) : NULL;
    if (encoding) (*env)->DeleteLocalRef(env, encoding);
    if (bytes) (*env)->DeleteLocalRef(env, bytes);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return result;
}
bool zj_char_sequence(JNIEnv *env, jobject view, const char *method, const char *value)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    if (!zj_clean(env) || !cls) return false;
    jmethodID set = (*env)->GetMethodID(env, cls, method, "(Ljava/lang/CharSequence;)V");
    jstring string = zj_string(env, value);
    bool ok = zj_clean(env) && set && string;
    if (ok) { (*env)->CallVoidMethod(env, view, set, string); ok = zj_clean(env); }
    if (string) (*env)->DeleteLocalRef(env, string);
    (*env)->DeleteLocalRef(env, cls); return ok;
}
bool zj_text(JNIEnv *env, jobject view, const char *value)
{
    return zj_char_sequence(env, view, "setText", value);
}
bool zj_append(JNIEnv *env, jobject group, jobject view)
{
    jclass cls = (*env)->GetObjectClass(env, group);
    if (!zj_clean(env) || !cls) return false;
    jmethodID add = (*env)->GetMethodID(env, cls, "addView", "(Landroid/view/View;)V");
    bool ok = zj_clean(env) && add;
    if (ok) { (*env)->CallVoidMethod(env, group, add, view); ok = zj_clean(env); }
    (*env)->DeleteLocalRef(env, cls); return ok;
}
bool zj_keep(JNIEnv *env, jobject *dest, jobject value)
{
    *dest = (*env)->NewGlobalRef(env, value);
    return zj_clean(env) && *dest;
}
bool zj_visible(JNIEnv *env, jobject view, bool visible)
{
    return zj_int_property(env, view, "setVisibility", visible ? 0 : 8);
}
/* Filled buttons are flat: the default elevation shadow is clipped by the bottom bar. */
bool zj_flatten(JNIEnv *env, jobject view)
{
    jmethodID animator = zj_method(env, view, "setStateListAnimator", "(Landroid/animation/StateListAnimator;)V");
    jmethodID elevation = animator ? zj_method(env, view, "setElevation", "(F)V") : NULL;
    if (!elevation) return false;
    (*env)->CallVoidMethod(env, view, animator, NULL);
    (*env)->CallVoidMethod(env, view, elevation, 0.0f);
    return zj_clean(env);
}
/* Fills the view with a rounded rectangle of the given color and corner radius. */
bool zj_pill(JNIEnv *env, jobject view, jint color, float radius_dp)
{
    jclass cls = (*env)->FindClass(env, "android/graphics/drawable/GradientDrawable");
    jmethodID ctor = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", "()V") : NULL;
    jobject shape = ctor ? (*env)->NewObject(env, cls, ctor) : NULL;
    jmethodID fill = zj_clean(env) && shape ? zj_method(env, shape, "setColor", "(I)V") : NULL;
    jmethodID round = fill ? zj_method(env, shape, "setCornerRadius", "(F)V") : NULL;
    jmethodID back = round ? zj_method(env, view, "setBackground", "(Landroid/graphics/drawable/Drawable;)V") : NULL;
    bool ok = back != NULL;
    if (ok) {
        (*env)->CallVoidMethod(env, shape, fill, color);
        (*env)->CallVoidMethod(env, shape, round, (jfloat)zj_dp(radius_dp));
        (*env)->CallVoidMethod(env, view, back, shape);
        ok = zj_clean(env);
    }
    if (shape) (*env)->DeleteLocalRef(env, shape);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
bool zj_margins(JNIEnv *env, jobject view, int width, int height, float weight, int left_dp, int top_dp, int right_dp, int bottom_dp)
{
    jclass cls = (*env)->FindClass(env, "android/widget/LinearLayout$LayoutParams");
    jmethodID ctor = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", "(IIF)V") : NULL;
    jmethodID margins = ctor ? (*env)->GetMethodID(env, cls, "setMargins", "(IIII)V") : NULL;
    jobject params = zj_clean(env) && margins ? (*env)->NewObject(env, cls, ctor, width, height, weight) : NULL;
    jmethodID set = zj_clean(env) && params ? zj_method(env, view, "setLayoutParams", "(Landroid/view/ViewGroup$LayoutParams;)V") : NULL;
    bool ok = set != NULL;
    if (ok) {
        (*env)->CallVoidMethod(env, params, margins, zj_dp((float)left_dp), zj_dp((float)top_dp), zj_dp((float)right_dp), zj_dp((float)bottom_dp));
        (*env)->CallVoidMethod(env, view, set, params);
        ok = zj_clean(env);
    }
    if (params) (*env)->DeleteLocalRef(env, params);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
bool zj_place(JNIEnv *env, jobject view, int width, int height, float weight, int bottom_dp)
{
    return zj_margins(env, view, width, height, weight, 0, 0, 0, bottom_dp);
}
bool zj_hit(JNIEnv *env, jobject view, float x, float y)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    if (!zj_clean(env) || !cls) return false;
    jmethodID location = (*env)->GetMethodID(env, cls, "getLocationInWindow", "([I)V");
    jmethodID width = (*env)->GetMethodID(env, cls, "getWidth", "()I");
    jmethodID height = (*env)->GetMethodID(env, cls, "getHeight", "()I");
    jmethodID visible = (*env)->GetMethodID(env, cls, "isShown", "()Z");
    jintArray pos = (*env)->NewIntArray(env, 2); jint xy[2] = {0};
    bool ok = zj_clean(env) && location && width && height && visible && pos;
    if (ok) {
        (*env)->CallVoidMethod(env, view, location, pos);
        (*env)->GetIntArrayRegion(env, pos, 0, 2, xy);
        jint w = (*env)->CallIntMethod(env, view, width), h = (*env)->CallIntMethod(env, view, height);
        jboolean shown = (*env)->CallBooleanMethod(env, view, visible);
        ok = zj_clean(env) && shown && x >= xy[0] && y >= xy[1] && x < xy[0] + w && y < xy[1] + h;
    }
    if (pos) (*env)->DeleteLocalRef(env, pos);
    (*env)->DeleteLocalRef(env, cls); return ok;
}
bool zj_copy_utf(JNIEnv *env, jstring value, char *out, size_t cap)
{
    const char *chars = zj_clean(env) && value ? (*env)->GetStringUTFChars(env, value, NULL) : NULL;
    bool ok = chars && strlen(chars) < cap;
    if (ok) memcpy(out, chars, strlen(chars) + 1);
    if (chars) (*env)->ReleaseStringUTFChars(env, value, chars);
    return ok;
}
static jobject decode_bitmap(JNIEnv *env, const unsigned char *bmp, size_t len)
{
    jclass factory = (*env)->FindClass(env, "android/graphics/BitmapFactory");
    jmethodID decode = factory ? (*env)->GetStaticMethodID(env, factory, "decodeByteArray", "([BII)Landroid/graphics/Bitmap;") : NULL;
    jbyteArray data = bmp && len ? (*env)->NewByteArray(env, (jsize)len) : NULL;
    if (data) (*env)->SetByteArrayRegion(env, data, 0, (jsize)len, (const jbyte *)bmp);
    jobject bitmap = zj_clean(env) && decode && data ? (*env)->CallStaticObjectMethod(env, factory, decode, data, 0, (jint)len) : NULL;
    return bitmap;
}
bool zj_bitmap(JNIEnv *env, jobject view, const unsigned char *bmp, size_t len)
{
    if (!view || len > 1024 * 1024) return false;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject bitmap = decode_bitmap(env, bmp, len);
    jclass image = (*env)->GetObjectClass(env, view);
    jmethodID set = image ? (*env)->GetMethodID(env, image, "setImageBitmap", "(Landroid/graphics/Bitmap;)V") : NULL;
    bool ok = zj_clean(env) && set && (!bmp || bitmap);
    if (ok) { (*env)->CallVoidMethod(env, view, set, bitmap); ok = zj_clean(env); }
    (void)zj_clean(env); (*env)->PopLocalFrame(env, NULL); return ok;
}
