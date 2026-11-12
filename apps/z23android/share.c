/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "share.h"
#include "share_media.h"
#include "base/cleanse.h"
#include "jni_util.h"
#include "payment_code.h"
#include "wallet_screens.h"
#include <stdio.h>
#include <string.h>

static char payment_code[ZAPP_RECEIVE_CODE_MAX];
static bool pending;
static bool media = true;

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
static bool put_allow_multiple(JNIEnv *env, jobject intent)
{
    jmethodID put = zj_method(env, intent, "putExtra", "(Ljava/lang/String;Z)Landroid/content/Intent;");
    jstring name = put ? zj_string(env, "android.intent.extra.ALLOW_MULTIPLE") : NULL;
    if (name) (*env)->CallObjectMethod(env, intent, put, name, true);
    return zj_clean(env) && name;
}
static bool put_uri_list(JNIEnv *env, jobject intent, jobject list)
{
    jmethodID put = zj_method(env, intent, "putParcelableArrayListExtra", "(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;");
    jstring name = put ? zj_string(env, "android.intent.extra.STREAM") : NULL;
    if (name) (*env)->CallObjectMethod(env, intent, put, name, list);
    return zj_clean(env) && name;
}
static bool set_clip_data(JNIEnv *env, jobject intent, jobject clip)
{
    jmethodID set = zj_method(env, intent, "setClipData", "(Landroid/content/ClipData;)V");
    if (set) (*env)->CallVoidMethod(env, intent, set, clip);
    return zj_clean(env) && set;
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
    jstring title = make ? zj_string(env, "Choose recipient") : NULL;
    jobject chooser = title ? (*env)->CallStaticObjectMethod(env, cls, make, intent, title) : NULL;
    jmethodID start = chooser ? zj_method(env, activity, "startActivityForResult", "(Landroid/content/Intent;I)V") : NULL;
    if (start) (*env)->CallVoidMethod(env, activity, start, chooser, ZAPP_SHARE_SEND_REQUEST);
    return zj_clean(env) && start;
}
static bool share_text(JNIEnv *env, jobject activity)
{
    bool ok = (*env)->PushLocalFrame(env, 16) == JNI_OK;
    if (ok) {
        jobject share = new_intent(env, "android.intent.action.SEND");
        ok = share && put_text(env, share, "android.intent.extra.TEXT", payment_code) &&
            set_type(env, share, "text/plain") && start_share(env, activity, share);
        (*env)->PopLocalFrame(env, NULL);
    }
    return ok;
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
static bool share_one_media(JNIEnv *env, jobject activity, jobject uri)
{
    bool ok = (*env)->PushLocalFrame(env, 16) == JNI_OK;
    if (ok) {
        jobject share = new_intent(env, "android.intent.action.SEND");
        ok = share && uri && put_text(env, share, "android.intent.extra.TEXT", payment_code) &&
            put_uri(env, share, "android.intent.extra.STREAM", uri) && add_read_grant(env, share) &&
            set_media_type(env, activity, share, uri) && start_share(env, activity, share);
        (*env)->PopLocalFrame(env, NULL);
    }
    return ok;
}
static int media_kind(JNIEnv *env, jobject resolver, jobject uri)
{
    jmethodID get = resolver ? zj_method(env, resolver, "getType", "(Landroid/net/Uri;)Ljava/lang/String;") : NULL;
    if (!get) return -1;
    jstring type = (*env)->CallObjectMethod(env, resolver, get, uri);
    if (!zj_clean(env)) return -1;
    if (!type) return 0;
    char name[64];
    bool copied = zj_copy_utf(env, type, name, sizeof(name));
    (*env)->DeleteLocalRef(env, type);
    if (!copied) return -1;
    if (!strncmp(name, "image/", 6)) return 1;
    if (!strncmp(name, "video/", 6)) return 2;
    return 3;
}
struct multi_media {
    jobject clip, resolver, list, share, grants, clip_type, item_type;
    jmethodID list_add, get_item, make, add, item_init;
    int kind;
};
static bool multi_setup(JNIEnv *env, jobject activity, jobject clip, jint count, struct multi_media *m)
{
    memset(m, 0, sizeof(*m));
    m->clip = clip;
    m->resolver = zj_object_property(env, activity, "getContentResolver", "()Landroid/content/ContentResolver;");
    jclass list_type = (*env)->FindClass(env, "java/util/ArrayList");
    jmethodID list_init = list_type ? (*env)->GetMethodID(env, list_type, "<init>", "(I)V") : NULL;
    m->list = list_init ? (*env)->NewObject(env, list_type, list_init, count) : NULL;
    m->list_add = zj_method(env, m->list, "add", "(Ljava/lang/Object;)Z");
    m->clip_type = (*env)->FindClass(env, "android/content/ClipData");
    m->make = m->clip_type ? (*env)->GetStaticMethodID(env, m->clip_type, "newUri",
        "(Landroid/content/ContentResolver;Ljava/lang/CharSequence;Landroid/net/Uri;)Landroid/content/ClipData;") : NULL;
    m->add = m->clip_type ? (*env)->GetMethodID(env, m->clip_type, "addItem", "(Landroid/content/ClipData$Item;)V") : NULL;
    m->item_type = (*env)->FindClass(env, "android/content/ClipData$Item");
    m->item_init = m->item_type ? (*env)->GetMethodID(env, m->item_type, "<init>", "(Landroid/net/Uri;)V") : NULL;
    m->get_item = zj_method(env, clip, "getItemAt", "(I)Landroid/content/ClipData$Item;");
    m->share = new_intent(env, "android.intent.action.SEND_MULTIPLE");
    return m->resolver && m->list && m->list_add && m->make && m->add && m->item_init && m->get_item && m->share;
}
static bool multi_add_grant(JNIEnv *env, struct multi_media *m, jobject uri, jint index)
{
    if (index == 0) {
        jstring label = zj_string(env, "Z23 media");
        m->grants = label ? (*env)->CallStaticObjectMethod(env, m->clip_type, m->make, m->resolver, label, uri) : NULL;
        return m->grants && zj_clean(env);
    }
    jobject added = m->grants ? (*env)->NewObject(env, m->item_type, m->item_init, uri) : NULL;
    if (!added) return false;
    (*env)->CallVoidMethod(env, m->grants, m->add, added);
    (*env)->DeleteLocalRef(env, added);
    return zj_clean(env);
}
static bool multi_append(JNIEnv *env, struct multi_media *m, jint index)
{
    jobject item = (*env)->CallObjectMethod(env, m->clip, m->get_item, index);
    jmethodID get_uri = item ? zj_method(env, item, "getUri", "()Landroid/net/Uri;") : NULL;
    jobject uri = get_uri ? (*env)->CallObjectMethod(env, item, get_uri) : NULL;
    if (!uri) { if (item) (*env)->DeleteLocalRef(env, item); return false; }
    bool ok = multi_add_grant(env, m, uri, index);
    if (ok) {
        (*env)->CallBooleanMethod(env, m->list, m->list_add, uri);
        int current = media_kind(env, m->resolver, uri);
        if (current < 0) ok = false;
        else m->kind = merge_media_kind(m->kind, current);
    }
    (*env)->DeleteLocalRef(env, uri);
    if (item) (*env)->DeleteLocalRef(env, item);
    return ok && zj_clean(env);
}
static bool share_multi_media(JNIEnv *env, jobject activity, jobject clip, jint count)
{
    bool ok = (*env)->PushLocalFrame(env, 32) == JNI_OK;
    if (ok) {
        struct multi_media m;
        ok = multi_setup(env, activity, clip, count, &m);
        /* The list carries the payload; matching ClipData grants every selected URI to the recipient. */
        for (jint i = 0; ok && i < count; ++i) ok = multi_append(env, &m, i);
        if (ok) {
            ok = m.grants && put_text(env, m.share, "android.intent.extra.TEXT", payment_code) &&
                put_uri_list(env, m.share, m.list) && set_clip_data(env, m.share, m.grants) && add_read_grant(env, m.share) &&
                set_type(env, m.share, m.kind == 1 ? "image/*" : m.kind == 2 ? "video/*" : "*/*") &&
                start_share(env, activity, m.share);
        }
        (*env)->PopLocalFrame(env, NULL);
    }
    return ok;
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
static bool prepare(bool with_media)
{
    if (pending) return false;
#ifdef ZAPP_SHARE_FIXTURE
    snprintf(payment_code, sizeof(payment_code), "zclassic:t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?amount=0.001");
#else
    if (!wallet_screens_share_code(payment_code, sizeof(payment_code))) return false;
#endif
    media = with_media;
    pending = true;
    return true;
}
bool zapp_share_prepare(void) { return prepare(true); }
bool zapp_share_prepare_text(void) { return prepare(false); }
bool zapp_share_begin(JNIEnv *env, jobject activity)
{
#ifdef ZAPP_SHARE_FIXTURE
    if (!pending) {
        media = true;
        pending = true;
        snprintf(payment_code, sizeof(payment_code), "zclassic:t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?amount=0.001");
    }
#endif
    if (!pending || !payment_code[0]) return false;
    if (!media) {
        bool ok = share_text(env, activity);
        if (!ok) zapp_share_destroy();
        return ok;
    }
    bool ok = (*env)->PushLocalFrame(env, 16) == JNI_OK;
    if (ok) {
        jobject picker = new_intent(env, "android.intent.action.OPEN_DOCUMENT");
        ok = picker && add_category(env, picker, "android.intent.category.OPENABLE") &&
            set_type(env, picker, "*/*") && put_media_types(env, picker) && put_allow_multiple(env, picker) &&
            add_read_grant(env, picker) && start_picker(env, activity, picker);
        (*env)->PopLocalFrame(env, NULL);
    }
    if (!ok) zapp_share_destroy();
    return ok;
}
enum picker_result { PICKER_FAILED, PICKER_LAUNCHED, PICKER_DONE };
static enum picker_result share_picker_data(JNIEnv *env, jobject activity, jobject data)
{
    bool ok = (*env)->PushLocalFrame(env, 32) == JNI_OK;
    if (!ok) return PICKER_FAILED;
    jobject clip = zj_object_property(env, data, "getClipData", "()Landroid/content/ClipData;");
    if (!clip) {
        jobject uri = zj_object_property(env, data, "getData", "()Landroid/net/Uri;");
        ok = share_one_media(env, activity, uri);
        (*env)->PopLocalFrame(env, NULL);
        return ok ? PICKER_LAUNCHED : PICKER_FAILED;
    }
    jmethodID count_method = zj_method(env, clip, "getItemCount", "()I");
    if (!count_method) { (*env)->PopLocalFrame(env, NULL); return PICKER_FAILED; }
    jint count = (*env)->CallIntMethod(env, clip, count_method);
    if (!zj_clean(env)) { (*env)->PopLocalFrame(env, NULL); return PICKER_FAILED; }
    if (!media_count_valid(count)) {
        return_with_notice(count <= 0 ? "No media was selected. Nothing was sent." :
            "Choose up to 32 photos or videos at a time. Nothing was sent.");
        zapp_share_destroy();
        (*env)->PopLocalFrame(env, NULL);
        return PICKER_DONE;
    }
    if (count > 1) ok = share_multi_media(env, activity, clip, count);
    else {
        jmethodID get_item = zj_method(env, clip, "getItemAt", "(I)Landroid/content/ClipData$Item;");
        jobject item = get_item ? (*env)->CallObjectMethod(env, clip, get_item, 0) : NULL;
        jmethodID get_uri = item ? zj_method(env, item, "getUri", "()Landroid/net/Uri;") : NULL;
        jobject uri = get_uri ? (*env)->CallObjectMethod(env, item, get_uri) : NULL;
        ok = share_one_media(env, activity, uri);
    }
    (*env)->PopLocalFrame(env, NULL);
    return ok ? PICKER_LAUNCHED : PICKER_FAILED;
}
bool zapp_share_result(JNIEnv *env, jobject activity, jint request, jint result, jobject data)
{
    if (request == ZAPP_SHARE_SEND_REQUEST) {
        /* Recipient launches and cancellations can share one result; neither result proves delivery. */
        if (result == -1) return_with_notice("Android completed the share action. Delivery is not confirmed.");
        else return_with_notice("Share sheet closed. Android does not confirm whether anything was sent.");
        zapp_share_destroy();
        return true;
    }
    if (request != ZAPP_SHARE_PICK_REQUEST) return true;
    if (result != -1 || !data) {
        return_with_notice("Share cancelled. Nothing was sent.");
        zapp_share_destroy();
        return true;
    }
    enum picker_result outcome = share_picker_data(env, activity, data);
    if (outcome == PICKER_DONE) return true;
    return_with_notice(outcome == PICKER_LAUNCHED ? "" : "Could not open the share sheet.");
    zapp_share_destroy();
    return outcome != PICKER_LAUNCHED;
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
        return_with_notice(media ? "Could not open the media picker." : "Could not open the share sheet.");
        finish_activity(env, activity);
    }
}
JNIEXPORT jint JNICALL Java_org_z23_nativeapp_ShareActivity_shareResultNative(JNIEnv *env, jobject activity,
    jint request, jint result, jobject data)
{
    return zapp_share_result(env, activity, request, result, data);
}
