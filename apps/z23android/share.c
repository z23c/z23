/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "share.h"
#include "base/cleanse.h"
#include "jni_util.h"
#include "payment_code.h"
#include "wallet_screens.h"
#include <stdio.h>
#include <string.h>
#include "share_diag.h"

static char payment_code[ZAPP_RECEIVE_CODE_MAX];
static bool pending;

static jobject new_intent(JNIEnv *env, const char *action)
{
    jclass cls = (*env)->FindClass(env, "android/content/Intent");
    jmethodID ctor = zj_clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;)V") : NULL;
    jstring name = ctor ? zj_string(env, action) : NULL;
    jobject intent = name ? (*env)->NewObject(env, cls, ctor, name) : NULL;
    return zj_clean(env) ? intent : NULL;
}
static bool put_text(JNIEnv *env, jobject intent, const char *key, const char *value)
{
    jmethodID put = zj_method(env, intent, "putExtra", "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;");
    jstring name = put ? zj_string(env, key) : NULL;
    jstring text = name ? zj_string(env, value) : NULL;
    if (text) (*env)->CallObjectMethod(env, intent, put, name, text);
    return zj_clean(env) && text;
}
static bool put_uri(JNIEnv *env, jobject intent, const char *key, jobject uri)
{
    jmethodID put = zj_method(env, intent, "putExtra", "(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;");
    jstring name = put ? zj_string(env, key) : NULL;
    if (name) (*env)->CallObjectMethod(env, intent, put, name, uri);
    return zj_clean(env) && name;
}
static bool put_media_types(JNIEnv *env, jobject intent)
{
    jclass string_cls = (*env)->FindClass(env, "java/lang/String");
    jobjectArray types = string_cls ? (*env)->NewObjectArray(env, 2, string_cls, NULL) : NULL;
    if (types) {
        (*env)->SetObjectArrayElement(env, types, 0, zj_string(env, "image/*"));
        (*env)->SetObjectArrayElement(env, types, 1, zj_string(env, "video/*"));
    }
    jmethodID put = types ? zj_method(env, intent, "putExtra", "(Ljava/lang/String;[Ljava/lang/String;)Landroid/content/Intent;") : NULL;
    jstring name = put ? zj_string(env, "android.intent.extra.MIME_TYPES") : NULL;
    if (name) (*env)->CallObjectMethod(env, intent, put, name, types);
    return zj_clean(env) && name;
}
static bool set_type(JNIEnv *env, jobject intent, const char *type)
{
    jmethodID set = zj_method(env, intent, "setType", "(Ljava/lang/String;)Landroid/content/Intent;");
    jstring value = set ? zj_string(env, type) : NULL;
    if (value) (*env)->CallObjectMethod(env, intent, set, value);
    return zj_clean(env) && value;
}
static bool add_category(JNIEnv *env, jobject intent, const char *category)
{
    jmethodID add = zj_method(env, intent, "addCategory", "(Ljava/lang/String;)Landroid/content/Intent;");
    jstring value = add ? zj_string(env, category) : NULL;
    if (value) (*env)->CallObjectMethod(env, intent, add, value);
    return zj_clean(env) && value;
}
static bool add_read_grant(JNIEnv *env, jobject intent)
{
    jmethodID add = zj_method(env, intent, "addFlags", "(I)Landroid/content/Intent;");
    if (add) (*env)->CallObjectMethod(env, intent, add, 1);
    return zj_clean(env) && add;
}
static bool start_picker(JNIEnv *env, jobject activity, jobject intent)
{
    jmethodID start = zj_method(env, activity, "startActivityForResult", "(Landroid/content/Intent;I)V");
    if (start) (*env)->CallVoidMethod(env, activity, start, intent, ZAPP_SHARE_PICK_REQUEST);
    return zj_clean(env) && start;
}
static bool start_share(JNIEnv *env, jobject activity, jobject intent)
{
    jclass cls = (*env)->FindClass(env, "android/content/Intent");
    jmethodID make = cls ? (*env)->GetStaticMethodID(env, cls, "createChooser",
        "(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;") : NULL;
    jstring title = make ? zj_string(env, "Share ZCL request and media") : NULL;
    jobject chooser = title ? (*env)->CallStaticObjectMethod(env, cls, make, intent, title) : NULL;
    jmethodID start = chooser ? zj_method(env, activity, "startActivity", "(Landroid/content/Intent;)V") : NULL;
    if (start) (*env)->CallVoidMethod(env, activity, start, chooser);
    return zj_clean(env) && start;
}
static bool set_media_type(JNIEnv *env, jobject activity, jobject intent, jobject uri)
{
    jobject resolver = zj_object_property(env, activity, "getContentResolver", "()Landroid/content/ContentResolver;");
    jmethodID get = resolver ? zj_method(env, resolver, "getType", "(Landroid/net/Uri;)Ljava/lang/String;") : NULL;
    jstring type = get ? (*env)->CallObjectMethod(env, resolver, get, uri) : NULL;
    jmethodID set = zj_method(env, intent, "setType", "(Ljava/lang/String;)Landroid/content/Intent;");
    jstring value = set ? (type ? type : zj_string(env, "application/octet-stream")) : NULL;
    if (value) (*env)->CallObjectMethod(env, intent, set, value);
    return zj_clean(env) && value;
}
static bool return_to_receive;
static char result_notice[96];

static void return_with_notice(const char *text)
{
    snprintf(result_notice, sizeof(result_notice), "%s", text);
    return_to_receive = true;
}
bool zapp_share_take_result(char *out, size_t cap)
{
    if (!return_to_receive) return false;
    SHARE_DIAG("share take text=%d", result_notice[0] ? 1 : 0);
    if (out && cap) snprintf(out, cap, "%s", result_notice);
    return_to_receive = false;
    result_notice[0] = '\0';
    return true;
}
void zapp_share_destroy(void)
{
    pending = false;
    memory_cleanse(payment_code, sizeof(payment_code));
}
bool zapp_share_prepare(void)
{
    if (pending) return false;
#ifdef ZAPP_SHARE_FIXTURE
    snprintf(payment_code, sizeof(payment_code), "zclassic:t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?amount=0.001");
#else
    if (!wallet_screens_share_code(payment_code, sizeof(payment_code))) return false;
#endif
    pending = true;
    return true;
}
bool zapp_share_begin(JNIEnv *env, jobject activity)
{
#ifdef ZAPP_SHARE_FIXTURE
    if (!pending) {
        pending = true;
        snprintf(payment_code, sizeof(payment_code), "zclassic:t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?amount=0.001");
    }
#endif
    if (!pending || !payment_code[0]) return false;
    bool ok = (*env)->PushLocalFrame(env, 16) == JNI_OK;
    if (ok) {
        jobject picker = new_intent(env, "android.intent.action.OPEN_DOCUMENT");
        ok = picker && add_category(env, picker, "android.intent.category.OPENABLE") &&
            set_type(env, picker, "*/*") && put_media_types(env, picker) &&
            add_read_grant(env, picker) && start_picker(env, activity, picker);
        (*env)->PopLocalFrame(env, NULL);
    }
    if (!ok) zapp_share_destroy();
    return ok;
}
void zapp_share_result(JNIEnv *env, jobject activity, jint request, jint result, jobject data)
{
    SHARE_DIAG("share result request=%ld result=%ld data=%d",
               (long)request, (long)result, !!data);
    if (request != ZAPP_SHARE_PICK_REQUEST) return;
    if (result != -1 || !data) {
        return_with_notice("Share cancelled. Nothing was sent.");
        zapp_share_destroy();
        return;
    }
    bool ok = (*env)->PushLocalFrame(env, 16) == JNI_OK;
    if (ok) {
        jobject share = new_intent(env, "android.intent.action.SEND");
        jobject uri = share ? zj_object_property(env, data, "getData", "()Landroid/net/Uri;") : NULL;
        ok = share && uri && put_text(env, share, "android.intent.extra.TEXT", payment_code) &&
            put_uri(env, share, "android.intent.extra.STREAM", uri) && add_read_grant(env, share) &&
            set_media_type(env, activity, share, uri) && start_share(env, activity, share);
        (*env)->PopLocalFrame(env, NULL);
    }
    return_with_notice(ok ? "" : "Could not open the share sheet.");
    zapp_share_destroy();
}

static void finish_activity(JNIEnv *env, jobject activity)
{
    jmethodID finish = zj_method(env, activity, "finish", "()V");
    if (finish) (*env)->CallVoidMethod(env, activity, finish);
    (void)zj_clean(env);
}
JNIEXPORT void JNICALL Java_org_z23_nativeapp_ShareActivity_shareCreate(JNIEnv *env, jobject activity)
{
    if (!zapp_share_begin(env, activity)) {
        return_with_notice("Could not open the media picker.");
        finish_activity(env, activity);
    }
}
JNIEXPORT void JNICALL Java_org_z23_nativeapp_ShareActivity_shareResultNative(JNIEnv *env, jobject activity,
    jint request, jint result, jobject data)
{
    zapp_share_result(env, activity, request, result, data);
    finish_activity(env, activity);
}
