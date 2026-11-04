/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jni_util.h"
#include "view_hit.h"
#include "native_ui.h"
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
bool zj_text_at_end(JNIEnv *env, jobject field, const char *value)
{
    if (!zj_text(env, field, value)) return false;
    jobject text = zj_object_property(env, field, "getText", "()Landroid/text/Editable;");
    jmethodID length = text ? zj_method(env, text, "length", "()I") : NULL;
    jint end = length ? (*env)->CallIntMethod(env, text, length) : 0;
    bool ok = zj_clean(env) && length && zj_int_property(env, field, "setSelection", end);
    if (text) (*env)->DeleteLocalRef(env, text);
    return ok;
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
/* A new object of a class with a public constructor that takes no argument, valid in the caller's local frame. */
static jobject plain_object(JNIEnv *env, const char *type)
{
    jclass cls = (*env)->FindClass(env, type);
    jmethodID ctor = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", "()V") : NULL;
    jobject obj = zj_clean(env) && ctor ? (*env)->NewObject(env, cls, ctor) : NULL;
    return zj_clean(env) ? obj : NULL;
}
/* Reads count int fields of obj, in order, into out. */
static bool int_fields(JNIEnv *env, jobject obj, const char *const names[], size_t count, jint *out)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    for (size_t i = 0; zj_clean(env) && cls && i < count; ++i) {
        jfieldID field = (*env)->GetFieldID(env, cls, names[i], "I");
        if (!zj_clean(env) || !field) return false;
        out[i] = (*env)->GetIntField(env, obj, field);
    }
    return zj_clean(env) && cls;
}
static bool view_part(JNIEnv *env, jobject part, jobject origin, struct zapp_view_box *box)
{
    static const char *const sides[] = {"left", "top", "right", "bottom"}, *const axes[] = {"x", "y"};
    jint sides_at[4] = {0}, origin_at[2] = {0};
    if (!zj_clean(env) || !int_fields(env, part, sides, 4, sides_at) || !int_fields(env, origin, axes, 2, origin_at)) return false;
    box->part_left = sides_at[0]; box->part_top = sides_at[1]; box->part_right = sides_at[2]; box->part_bottom = sides_at[3];
    box->part_origin_x = origin_at[0]; box->part_origin_y = origin_at[1];
    return true;
}
/* The bounds of the view in the window and the part of it on screen. Call inside a local frame. */
static bool view_box(JNIEnv *env, jobject view, struct zapp_view_box *box)
{
    jobject part = plain_object(env, "android/graphics/Rect"), origin = part ? plain_object(env, "android/graphics/Point") : NULL;
    jintArray at = origin ? (*env)->NewIntArray(env, 2) : NULL;
    jmethodID location = zj_clean(env) && at ? zj_method(env, view, "getLocationInWindow", "([I)V") : NULL;
    jmethodID width = location ? zj_method(env, view, "getWidth", "()I") : NULL, height = width ? zj_method(env, view, "getHeight", "()I") : NULL;
    jmethodID shown = height ? zj_method(env, view, "isShown", "()Z") : NULL;
    jmethodID visible = shown ? zj_method(env, view, "getGlobalVisibleRect", "(Landroid/graphics/Rect;Landroid/graphics/Point;)Z") : NULL;
    jint xy[2] = {0};
    if (!visible) return false;
    (*env)->CallVoidMethod(env, view, location, at);
    if (!zj_clean(env)) return false;
    (*env)->GetIntArrayRegion(env, at, 0, 2, xy);
    box->left = xy[0]; box->top = xy[1];
    box->width = (*env)->CallIntMethod(env, view, width);
    box->height = zj_clean(env) ? (*env)->CallIntMethod(env, view, height) : 0;
    box->shown = zj_clean(env) && (*env)->CallBooleanMethod(env, view, shown);
    box->visible = zj_clean(env) && (*env)->CallBooleanMethod(env, view, visible, part, origin);
    return view_part(env, part, origin, box);
}
bool zj_hit(JNIEnv *env, jobject view, float x, float y)
{
    struct zapp_view_box box = {0};
    if (!view || (*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)zj_clean(env); return false; }
    bool read = view_box(env, view, &box);
    (void)zj_clean(env);
    (*env)->PopLocalFrame(env, NULL);
    return read && zapp_view_hit(&box, x, y);
}
bool zj_focused(JNIEnv *env, jobject view)
{
    jmethodID focused = view ? zj_method(env, view, "isFocused", "()Z") : NULL;
    bool yes = focused && (*env)->CallBooleanMethod(env, view, focused);
    return zj_clean(env) && yes;
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
/* The input method service, valid in the caller's local frame. */
static jobject input_methods(JNIEnv *env, jobject activity)
{
    jstring name = zj_string(env, "input_method");
    jmethodID get = name ? zj_method(env, activity, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;") : NULL;
    jobject service = get ? (*env)->CallObjectMethod(env, activity, get, name) : NULL;
    return zj_clean(env) ? service : NULL;
}
/* The keyboard asked for through the insets of the field's window, for a service that refused the field. */
static bool show_by_insets(JNIEnv *env, jobject view)
{
    jobject controller = zj_object_property(env, view, "getWindowInsetsController", "()Landroid/view/WindowInsetsController;");
    jclass type = controller ? (*env)->FindClass(env, "android/view/WindowInsets$Type") : NULL;
    jmethodID ime = type && zj_clean(env) ? (*env)->GetStaticMethodID(env, type, "ime", "()I") : NULL;
    jint mask = ime && zj_clean(env) ? (*env)->CallStaticIntMethod(env, type, ime) : 0;
    jmethodID show = mask && zj_clean(env) ? zj_method(env, controller, "show", "(I)V") : NULL;
    if (show) (*env)->CallVoidMethod(env, controller, show, mask);
    return show && zj_clean(env);
}
static bool show_keyboard(JNIEnv *env, jobject service, jobject view)
{
    jmethodID focus = zj_method(env, view, "requestFocus", "()Z");
    jmethodID open = focus ? zj_method(env, service, "showSoftInput", "(Landroid/view/View;I)Z") : NULL;
    bool focused = open && (*env)->CallBooleanMethod(env, view, focus) && zj_clean(env);
    bool ok = focused && (*env)->CallBooleanMethod(env, service, open, view, 0) && zj_clean(env);
    return ok || (focused && show_by_insets(env, view));
}
static bool hide_keyboard(JNIEnv *env, jobject service, jobject view)
{
    jobject token = zj_object_property(env, view, "getWindowToken", "()Landroid/os/IBinder;");
    jmethodID hide = token ? zj_method(env, service, "hideSoftInputFromWindow", "(Landroid/os/IBinder;I)Z") : NULL;
    return hide && (*env)->CallBooleanMethod(env, service, hide, token, 0) && zj_clean(env);
}
bool zj_keyboard(JNIEnv *env, jobject activity, jobject view, bool show)
{
    if (!activity || !view || (*env)->PushLocalFrame(env, 12) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject service = input_methods(env, activity);
    bool ok = service && (show ? show_keyboard(env, service, view) : hide_keyboard(env, service, view));
    (void)zj_clean(env);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}

static jboolean editor_action(JNIEnv *env, jobject listener, jobject view, jint action, jobject event)
{
    (void)listener; (void)event;
    return action == 2 && zapp_native_ui_editor(env, view) ? JNI_TRUE : JNI_FALSE;
}

bool zj_editor_listener(JNIEnv *env, jobject view)
{
    if (!view || (*env)->PushLocalFrame(env, 12) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject context = zj_object_property(env, view, "getContext", "()Landroid/content/Context;");
    jobject loader = context ? zj_object_property(env, context, "getClassLoader", "()Ljava/lang/ClassLoader;") : NULL;
    jmethodID load = loader ? zj_method(env, loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;") : NULL;
    jstring name = load ? (*env)->NewStringUTF(env, "org.z23.nativeapp.KeyPrompt") : NULL;
    jclass cls = name ? (jclass)(*env)->CallObjectMethod(env, loader, load, name) : NULL;
    static const JNINativeMethod native[] = {
        {"onEditorAction", "(Landroid/widget/TextView;ILandroid/view/KeyEvent;)Z", (void *)editor_action}
    };
    bool ok = zj_clean(env) && cls && (*env)->RegisterNatives(env, cls, native, 1) == JNI_OK && zj_clean(env);
    jmethodID ctor = ok ? (*env)->GetMethodID(env, cls, "<init>", "()V") : NULL;
    jobject listener = ctor ? (*env)->NewObject(env, cls, ctor) : NULL;
    jmethodID set = listener ? zj_method(env, view, "setOnEditorActionListener", "(Landroid/widget/TextView$OnEditorActionListener;)V") : NULL;
    if (set) (*env)->CallVoidMethod(env, view, set, listener);
    ok = set && zj_clean(env);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
