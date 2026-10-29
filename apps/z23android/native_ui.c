/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "native_ui.h"
#include "fleet.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static jobject root, status_view, output_view, prompt_view, invite_view, camera_view, balance_view;
static jobject connection_view, transcript_view, fleet_view, receipt_view, details_view, notice_view;
static jobject buttons[9];
static bool details_open;
static enum zapp_reply_state reply_state;
static zapp_native_action callback;
static int pressed = -1;
static float down_x, down_y;
static char last_receipt[8192];
static const char *const actions[] = {"node_start", "node_stop", "operation", "chat", "fleet_scan", "fleet_preview", "fleet_join", "fleet_refresh"};

static bool clean(JNIEnv *env)
{
    if (!(*env)->ExceptionCheck(env)) return true;
    (*env)->ExceptionClear(env); return false;
}
static jobject widget(JNIEnv *env, const char *type, jobject activity)
{
    jclass cls = (*env)->FindClass(env, type);
    if (!clean(env) || !cls) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(Landroid/content/Context;)V");
    jobject obj = ctor ? (*env)->NewObject(env, cls, ctor, activity) : NULL;
    if (!clean(env)) obj = NULL;
    (*env)->DeleteLocalRef(env, cls); return obj;
}
static jstring make_string(JNIEnv *env, const char *value)
{
    size_t length = strlen(value);
    jclass cls = (*env)->FindClass(env, "java/lang/String");
    jmethodID ctor = cls ? (*env)->GetMethodID(env, cls, "<init>", "([BLjava/lang/String;)V") : NULL;
    jbyteArray bytes = length <= 65536 ? (*env)->NewByteArray(env, (jsize)length) : NULL;
    jstring encoding = (*env)->NewStringUTF(env, "UTF-8");
    if (bytes) (*env)->SetByteArrayRegion(env, bytes, 0, (jsize)length, (const jbyte *)value);
    jstring result = clean(env) && ctor && bytes && encoding ? (*env)->NewObject(env, cls, ctor, bytes, encoding) : NULL;
    if (encoding) (*env)->DeleteLocalRef(env, encoding);
    if (bytes) (*env)->DeleteLocalRef(env, bytes);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return result;
}
static bool text(JNIEnv *env, jobject view, const char *value)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    if (!clean(env) || !cls) return false;
    jmethodID set = (*env)->GetMethodID(env, cls, "setText", "(Ljava/lang/CharSequence;)V");
    jstring string = make_string(env, value);
    bool ok = clean(env) && set && string;
    if (ok) { (*env)->CallVoidMethod(env, view, set, string); ok = clean(env); }
    if (string) (*env)->DeleteLocalRef(env, string);
    (*env)->DeleteLocalRef(env, cls); return ok;
}
static bool append(JNIEnv *env, jobject layout, jobject view)
{
    jclass cls = (*env)->GetObjectClass(env, layout);
    if (!clean(env) || !cls) return false;
    jmethodID add = (*env)->GetMethodID(env, cls, "addView", "(Landroid/view/View;)V");
    bool ok = clean(env) && add;
    if (ok) { (*env)->CallVoidMethod(env, layout, add, view); ok = clean(env); }
    (*env)->DeleteLocalRef(env, cls); return ok;
}
static bool keep(JNIEnv *env, jobject *dest, jobject value)
{
    *dest = (*env)->NewGlobalRef(env, value);
    return clean(env) && *dest;
}
static bool add_text(JNIEnv *env, jobject layout, jobject activity, const char *label, jobject *save)
{
    jobject view = widget(env, "android/widget/TextView", activity);
    bool ok = view && text(env, view, label) && append(env, layout, view) && (!save || keep(env, save, view));
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool add_button(JNIEnv *env, jobject layout, jobject activity, const char *label, size_t i)
{
    jobject view = widget(env, "android/widget/Button", activity);
    bool ok = view && text(env, view, label) && append(env, layout, view) && keep(env, &buttons[i], view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
void zapp_native_ui_destroy(JNIEnv *env)
{
    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); ++i) {
        if (buttons[i]) (*env)->DeleteGlobalRef(env, buttons[i]);
        buttons[i] = NULL;
    }
    jobject *views[] = {&root, &status_view, &balance_view, &output_view, &notice_view, &details_view, &prompt_view, &invite_view, &camera_view, &connection_view, &transcript_view, &fleet_view, &receipt_view};
    for (size_t i = 0; i < sizeof(views) / sizeof(views[0]); ++i) {
        if (*views[i]) (*env)->DeleteGlobalRef(env, *views[i]);
        *views[i] = NULL;
    }
    callback = NULL; pressed = -1; details_open = false; reply_state = ZAPP_REPLY_READY; last_receipt[0] = 0;
}
static bool node_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject camera, jobject receipt, jobject scroll)
{
    (void)prompt; (void)invite; (void)camera; (void)receipt; (void)scroll;
    return !(!add_text(env, layout, activity, "Z23", NULL) ||
        !add_text(env, layout, activity, "Balance unavailable", &balance_view) ||
        !add_text(env, layout, activity, "Node status unknown", &status_view) ||
        !add_text(env, layout, activity, "", &notice_view));
}
static bool chat_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject camera, jobject receipt, jobject scroll)
{
    (void)prompt; (void)invite; (void)camera; (void)receipt; (void)scroll;
    return !(        !add_text(env, layout, activity, "Chat", NULL) ||
        !add_text(env, layout, activity, "Not connected", &connection_view) ||
        !add_text(env, layout, activity, "", &transcript_view) ||
        !append(env, layout, prompt) || !keep(env, &prompt_view, prompt) ||
        !add_button(env, layout, activity, "Send", 3) ||
        !add_button(env, layout, activity, "Details", 8));
}
static bool detail_controls(JNIEnv *env, jobject layout, jobject activity)
{
    return add_button(env, layout, activity, "Start node", 0) &&
        add_button(env, layout, activity, "Stop node", 1) &&
        add_button(env, layout, activity, "Check status", 2) &&
        add_text(env, layout, activity, "Fleet invitation", NULL);
}
static bool fleet_widgets(JNIEnv *env, jobject layout, jobject activity, jobject prompt, jobject invite, jobject camera, jobject receipt, jobject scroll)
{
    (void)prompt; (void)invite; (void)camera; (void)receipt; (void)scroll;
    return !(!detail_controls(env, layout, activity) ||
        !add_button(env, layout, activity, "Scan invitation", 4) ||
        !append(env, layout, camera) || !keep(env, &camera_view, camera) ||
        !append(env, layout, invite) || !keep(env, &invite_view, invite) ||
        !add_button(env, layout, activity, "Review invitation", 5) ||
        !add_button(env, layout, activity, "Trust manager and join", 6) ||
        !add_button(env, layout, activity, "Refresh fleet status", 7) ||
        !add_text(env, layout, activity, "", &fleet_view));
}
static bool finish_widgets(JNIEnv *env, jobject layout, jobject activity, jobject receipt)
{
    return !(!append(env, layout, receipt) || !keep(env, &receipt_view, receipt) ||
        !add_text(env, layout, activity, "", &output_view));
}
static bool orient_layout(JNIEnv *env, jobject layout)
{
    jclass cls = (*env)->GetObjectClass(env, layout);
    jmethodID method = cls ? (*env)->GetMethodID(env, cls, "setOrientation", "(I)V") : NULL;
    if (!clean(env) || !method) return false;
    (*env)->CallVoidMethod(env, layout, method, 1);
    return clean(env);
}
static bool set_visible(JNIEnv *env, jobject view, bool visible)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    jmethodID set = cls ? (*env)->GetMethodID(env, cls, "setVisibility", "(I)V") : NULL;
    bool ok = clean(env) && set;
    if (ok) { (*env)->CallVoidMethod(env, view, set, visible ? 0 : 8); ok = clean(env); }
    if (cls) (*env)->DeleteLocalRef(env, cls);
    return ok;
}
static bool show_root(JNIEnv *env, jobject activity, jobject scroll)
{
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID method = cls ? (*env)->GetMethodID(env, cls, "setContentView", "(Landroid/view/View;)V") : NULL;
    if (!clean(env) || !method) return false;
    (*env)->CallVoidMethod(env, activity, method, scroll);
    return clean(env);
}
static bool prepare_layouts(JNIEnv *env, jobject scroll, jobject layout,
                            jobject details, jobject prompt, jobject invite,
                            jobject camera, jobject receipt)
{
    return scroll && layout && prompt && invite && camera && receipt && details &&
           orient_layout(env, layout) && orient_layout(env, details);
}
static bool attach_details(JNIEnv *env, jobject details, jobject layout, jobject scroll)
{
    return set_visible(env, details, false) && append(env, layout, details) &&
           keep(env, &details_view, details) && append(env, scroll, layout) &&
           keep(env, &root, scroll);
}
bool zapp_native_ui_create(JNIEnv *env, jobject activity, zapp_native_action action)
{
    if (!env || !activity || !action || root) return false;
    if ((*env)->PushLocalFrame(env, 32) != JNI_OK) { (void)clean(env); return false; }
    bool ok = false;
    jobject scroll = widget(env, "android/widget/ScrollView", activity);
    jobject layout = widget(env, "android/widget/LinearLayout", activity);
    jobject details = widget(env, "android/widget/LinearLayout", activity);
    jobject prompt = widget(env, "android/widget/EditText", activity);
    jobject invite = widget(env, "android/widget/EditText", activity);
    jobject camera = widget(env, "android/widget/ImageView", activity);
    jobject receipt = widget(env, "android/widget/ImageView", activity);
    if (!prepare_layouts(env, scroll, layout, details, prompt, invite, camera, receipt)) goto out;
    if (!node_widgets(env, layout, activity, prompt, invite, camera, receipt, scroll) ||
        !chat_widgets(env, layout, activity, prompt, invite, camera, receipt, scroll) ||
        !fleet_widgets(env, details, activity, prompt, invite, camera, receipt, scroll) ||
        !finish_widgets(env, details, activity, receipt) ||
        !attach_details(env, details, layout, scroll)) goto out;
    if (!show_root(env, activity, scroll)) goto out;
    callback = action; ok = true;
out:
    (void)clean(env);
    (*env)->PopLocalFrame(env, NULL);
    if (!ok) zapp_native_ui_destroy(env);
    return ok;
}
static void emit_utf8(char *out, size_t *used, uint32_t cp)
{
                if (cp < 0x80) out[(*used)++] = (char)cp;
                else if (cp < 0x800) { out[(*used)++] = (char)(0xc0 | (cp >> 6)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
                else if (cp < 0x10000) { out[(*used)++] = (char)(0xe0 | (cp >> 12)); out[(*used)++] = (char)(0x80 | ((cp >> 6) & 63)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
                else { out[(*used)++] = (char)(0xf0 | (cp >> 18)); out[(*used)++] = (char)(0x80 | ((cp >> 12) & 63)); out[(*used)++] = (char)(0x80 | ((cp >> 6) & 63)); out[(*used)++] = (char)(0x80 | (cp & 63)); }
}
static char *encode_prompt(const jchar *chars, jsize n)
{
    char *out = NULL;
    out = malloc((size_t)n * 3 + 1); size_t used = 0;
            if (out) for (jsize i = 0; i < n; ++i) {
                uint32_t cp = chars[i];
                if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < n && chars[i + 1] >= 0xdc00 && chars[i + 1] <= 0xdfff)
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (chars[++i] - 0xdc00);
                else if (!cp || (cp >= 0xd800 && cp <= 0xdfff)) { free(out); out = NULL; break; }
                emit_utf8(out, &used, cp);
            }
            if (out) out[used] = 0;
    return out;
}
static char *string_utf8(JNIEnv *env, jstring string)
{
    jsize n = (*env)->GetStringLength(env, string);
    const jchar *chars = (*env)->GetStringChars(env, string, NULL);
    char *out = NULL;
    if (clean(env) && chars && n <= 16000) out = encode_prompt(chars, n);
    if (chars) (*env)->ReleaseStringChars(env, string, chars);
    return out;
}
static char *prompt_utf8(JNIEnv *env, jobject field)
{
    jclass cls = (*env)->GetObjectClass(env, field);
    if (!clean(env) || !cls) return NULL;
    jmethodID get = (*env)->GetMethodID(env, cls, "getText", "()Landroid/text/Editable;");
    jobject editable = get ? (*env)->CallObjectMethod(env, field, get) : NULL;
    if (!clean(env) || !editable) { (*env)->DeleteLocalRef(env, cls); return NULL; }
    jclass edit_class = (*env)->GetObjectClass(env, editable);
    jmethodID to_string = edit_class ? (*env)->GetMethodID(env, edit_class, "toString", "()Ljava/lang/String;") : NULL;
    jstring string = to_string ? (*env)->CallObjectMethod(env, editable, to_string) : NULL;
    char *out = NULL;
    if (clean(env) && string) out = string_utf8(env, string);
    (void)clean(env);
    if (string) (*env)->DeleteLocalRef(env, string);
    if (edit_class) (*env)->DeleteLocalRef(env, edit_class);
    (*env)->DeleteLocalRef(env, editable); (*env)->DeleteLocalRef(env, cls);
    return out;
}
static bool hit(JNIEnv *env, jobject view, float x, float y)
{
    jclass cls = (*env)->GetObjectClass(env, view);
    if (!clean(env) || !cls) return false;
    jmethodID location = (*env)->GetMethodID(env, cls, "getLocationInWindow", "([I)V");
    jmethodID width = (*env)->GetMethodID(env, cls, "getWidth", "()I");
    jmethodID height = (*env)->GetMethodID(env, cls, "getHeight", "()I");
    jmethodID visible = (*env)->GetMethodID(env, cls, "isShown", "()Z");
    jintArray pos = (*env)->NewIntArray(env, 2); jint xy[2] = {0};
    bool ok = clean(env) && location && width && height && visible && pos;
    if (ok) {
        (*env)->CallVoidMethod(env, view, location, pos);
        (*env)->GetIntArrayRegion(env, pos, 0, 2, xy);
        jint w = (*env)->CallIntMethod(env, view, width), h = (*env)->CallIntMethod(env, view, height);
        jboolean shown = (*env)->CallBooleanMethod(env, view, visible);
        ok = clean(env) && shown && x >= xy[0] && y >= xy[1] && x < xy[0] + w && y < xy[1] + h;
    }
    if (pos) (*env)->DeleteLocalRef(env, pos);
    (*env)->DeleteLocalRef(env, cls); return ok;
}
static void input_up(JNIEnv *env, float x, float y)
{
        int index = pressed; pressed = -1;
        if (index < 0 || !hit(env, buttons[index], x, y)) return;
        if (index == 8) {
            bool next = !details_open;
            if (set_visible(env, details_view, next)) details_open = next;
            return;
        }
        if (index == 3 && reply_state != ZAPP_REPLY_READY) {
            callback("chat_cancel", "");
            return;
        }
        bool needs_text = index == 3 || index == 5;
        char *value = needs_text ? prompt_utf8(env, index == 3 ? prompt_view : invite_view) : NULL;
        if (!needs_text || value) callback(actions[index], value ? value : index == 2 ? "status" : "");
        if (value) { memset(value, 0, strlen(value)); free(value); }
}
void zapp_native_ui_input(JNIEnv *env, const AInputEvent *event)
{
    if (!callback || !event || AInputEvent_getType(event) != AINPUT_EVENT_TYPE_MOTION) return;
    int32_t action = AMotionEvent_getAction(event) & AMOTION_EVENT_ACTION_MASK;
    float x = AMotionEvent_getX(event, 0), y = AMotionEvent_getY(event, 0);
    if (action == AMOTION_EVENT_ACTION_DOWN) {
        pressed = -1; down_x = x; down_y = y;
        for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); ++i)
            if (buttons[i] && hit(env, buttons[i], x, y)) { pressed = (int)i; break; }
    } else if (action == AMOTION_EVENT_ACTION_MOVE) {
        if (x - down_x > 20 || down_x - x > 20 || y - down_y > 20 || down_y - y > 20) pressed = -1;
    } else if (action == AMOTION_EVENT_ACTION_CANCEL) pressed = -1;
    else if (action == AMOTION_EVENT_ACTION_UP) input_up(env, x, y);
}
void zapp_native_ui_update(JNIEnv *env, const char *status, const char *output)
{
    if (status_view && status) (void)text(env, status_view, status);
    if (output_view && output) (void)text(env, output_view, output);
}

static jobject decode_bitmap(JNIEnv *env, const unsigned char *bmp, size_t len)
{
    jclass factory = (*env)->FindClass(env, "android/graphics/BitmapFactory");
    jmethodID decode = factory ? (*env)->GetStaticMethodID(env, factory, "decodeByteArray", "([BII)Landroid/graphics/Bitmap;") : NULL;
    jbyteArray data = bmp && len ? (*env)->NewByteArray(env, (jsize)len) : NULL;
    if (data) (*env)->SetByteArrayRegion(env, data, 0, (jsize)len, (const jbyte *)bmp);
    jobject bitmap = clean(env) && decode && data ? (*env)->CallStaticObjectMethod(env, factory, decode, data, 0, (jint)len) : NULL;
    return bitmap;
}
static bool set_bitmap(JNIEnv *env, jobject view, const unsigned char *bmp, size_t len)
{
    if (!view || len > 1024 * 1024) return false;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return false; }
    jobject bitmap = decode_bitmap(env, bmp, len);
    jclass image = (*env)->GetObjectClass(env, view);
    jmethodID set = image ? (*env)->GetMethodID(env, image, "setImageBitmap", "(Landroid/graphics/Bitmap;)V") : NULL;
    bool ok = clean(env) && set && (!bmp || bitmap);
    if (ok) { (*env)->CallVoidMethod(env, view, set, bitmap); ok = clean(env); }
    (void)clean(env); (*env)->PopLocalFrame(env, NULL); return ok;
}

void zapp_native_ui_preview(JNIEnv *env, const unsigned char *bmp, size_t len)
{ (void)set_bitmap(env, camera_view, bmp, len); }

static void receipt_qr(JNIEnv *env, const char *value)
{
    if (!strcmp(last_receipt, value)) return;
    last_receipt[0] = 0;
    if (!*value) { (void)set_bitmap(env, receipt_view, NULL, 0); return; }
    size_t size = 0;
    unsigned char *bmp = zapp_fleet_qr_bmp(value, &size);
    bool shown = bmp && set_bitmap(env, receipt_view, bmp, size);
    free(bmp);
    if (shown && strlen(value) < sizeof(last_receipt)) memcpy(last_receipt, value, strlen(value) + 1);
    else (void)set_bitmap(env, receipt_view, NULL, 0);
}
void zapp_native_ui_render(JNIEnv *env, const struct zapp_view *view)
{
    if (!env || !view) return;
    reply_state = view->reply_state;
    const char *send_label = reply_state == ZAPP_REPLY_WAITING ? "Stop reply" :
        reply_state == ZAPP_REPLY_CANCELLING ? "Stopping…" : "Send";
    if (buttons[3]) (void)text(env, buttons[3], send_label);
    char status[1400];
    snprintf(status, sizeof(status), "Node: %s%s\n%s", view->node_running ? "responding" : "unavailable",
             view->busy ? " · working" : "", view->sync_status[0] ? view->sync_status : "Sync status unknown");
    (void)text(env, status_view, status);
    char balance[600];
    snprintf(balance, sizeof(balance), "%s%s", view->balance_stale ? "Last observed (stale):\n" : "",
             view->balance[0] ? view->balance : "Balance unavailable");
    (void)text(env, balance_view, balance);
    (void)text(env, connection_view, view->connection[0] ? view->connection : "Connect a laptop to use chat.");
    (void)text(env, transcript_view, view->transcript);
    char fleet[18432];
    snprintf(fleet, sizeof(fleet), "%s%s%s%s%s", view->fleet_preview,
             view->fleet_preview[0] && view->fleet_status[0] ? "\n" : "", view->fleet_status,
             view->fleet_receipt[0] ? "\nReceipt: " : "", view->fleet_receipt);
    (void)text(env, fleet_view, fleet);
    (void)text(env, notice_view, view->notice);
    (void)text(env, output_view, view->output);
    receipt_qr(env, view->fleet_receipt);
}
